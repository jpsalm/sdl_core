/*

 Copyright (c) 2018, Ford Motor Company
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following
 disclaimer in the documentation and/or other materials provided with the
 distribution.

 Neither the name of the Ford Motor Company nor the names of its contributors
 may be used to endorse or promote products derived from this software
 without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 */

#include "sdl_rpc_plugin/commands/mobile/perform_interaction_request.h"

#include <string.h>
#include <limits>
#include <numeric>
#include <string>

#include "application_manager/application_impl.h"
#include "application_manager/message_helper.h"

#include "interfaces/HMI_API.h"
#include "interfaces/MOBILE_API.h"
#include "utils/custom_string.h"
#include "utils/file_system.h"
#include "utils/gen_hash.h"
#include "utils/helpers.h"

namespace {
const std::int32_t INVALID_CHOICE_ID = std::numeric_limits<std::int32_t>::max();
}

namespace sdl_rpc_plugin {
using namespace application_manager;

namespace commands {

namespace custom_str = utils::custom_string;

uint32_t PerformInteractionRequest::pi_requests_count_ = 0;

PerformInteractionRequest::PerformInteractionRequest(
    const application_manager::commands::MessageSharedPtr& message,
    ApplicationManager& application_manager,
    app_mngr::rpc_service::RPCService& rpc_service,
    app_mngr::HMICapabilities& hmi_capabilities,
    policy::PolicyHandlerInterface& policy_handler)
    : CommandRequestImpl(message,
                         application_manager,
                         rpc_service,
                         hmi_capabilities,
                         policy_handler)
    , interaction_mode_(mobile_apis::InteractionMode::INVALID_ENUM)
    , ui_choice_id_received_(INVALID_CHOICE_ID)
    , vr_choice_id_received_(INVALID_CHOICE_ID)
    , ui_response_received_(false)
    , vr_response_received_(false)
    , app_pi_was_active_before_(false)
    , vr_result_code_(hmi_apis::Common_Result::INVALID_ENUM)
    , ui_result_code_(hmi_apis::Common_Result::INVALID_ENUM)
    , vr_params_(smart_objects::SmartObject(smart_objects::SmartType_Map))
    , first_responder_(FirstAnsweredInterface::NONE) {
  subscribe_on_event(hmi_apis::FunctionID::UI_OnResetTimeout);
  subscribe_on_event(hmi_apis::FunctionID::VR_OnCommand);
  subscribe_on_event(hmi_apis::FunctionID::Buttons_OnButtonPress);
}

PerformInteractionRequest::~PerformInteractionRequest() {}

bool PerformInteractionRequest::Init() {
  /* Timeout in milliseconds.
     If omitted a standard value of 10000 milliseconds is used.*/
  const auto& msg_params = (*message_)[strings::msg_params];
  uint32_t request_timeout = msg_params[strings::timeout].asUInt();

  interaction_mode_ = static_cast<mobile_apis::InteractionMode::eType>(
      msg_params[strings::interaction_mode].asInt());

  if (mobile_apis::InteractionMode::BOTH == interaction_mode_ ||
      mobile_apis::InteractionMode::MANUAL_ONLY == interaction_mode_) {
    const uint32_t increase_value = 2;
    default_timeout_ += request_timeout * increase_value;
  } else {
    default_timeout_ += request_timeout;
  }
  return true;
}

void PerformInteractionRequest::Run() {
  LOG4CXX_AUTO_TRACE(logger_);

  ApplicationSharedPtr app = application_manager_.application(connection_key());

  if (!app) {
    LOG4CXX_ERROR(logger_, "Application is not registered");
    SendResponse(false, mobile_apis::Result::APPLICATION_NOT_REGISTERED);
    return;
  }

  if (app->is_perform_interaction_active()) {
    LOG4CXX_DEBUG(logger_, "Application has active PerformInteraction");
    app_pi_was_active_before_ = true;
  }

  smart_objects::SmartObject& msg_params = (*message_)[strings::msg_params];
  mobile_apis::LayoutMode::eType interaction_layout =
      mobile_apis::LayoutMode::INVALID_ENUM;

  if (msg_params.keyExists(hmi_request::interaction_layout)) {
    interaction_layout = static_cast<mobile_apis::LayoutMode::eType>(
        msg_params[hmi_request::interaction_layout].asInt());
  }

  if ((mobile_apis::InteractionMode::VR_ONLY == interaction_mode_) &&
      (mobile_apis::LayoutMode::KEYBOARD == interaction_layout)) {
    LOG4CXX_ERROR(logger_,
                  "PerformInteraction contains InteractionMode"
                  "=VR_ONLY and interactionLayout=KEYBOARD");
    SendResponse(false, mobile_apis::Result::INVALID_DATA);
    return;
  }

  const size_t choice_set_id_list_length =
      msg_params[strings::interaction_choice_set_id_list].length();

  if (0 == choice_set_id_list_length) {
    if (mobile_apis::LayoutMode::KEYBOARD == interaction_layout) {
      if (mobile_apis::InteractionMode::BOTH == interaction_mode_) {
        LOG4CXX_ERROR(logger_,
                      "interactionChoiceSetIDList is empty,"
                      " InteractionMode=BOTH and"
                      " interactionLayout=KEYBOARD");
        SendResponse(false, mobile_apis::Result::INVALID_DATA);
        return;
      }
    } else {
      LOG4CXX_ERROR(logger_,
                    "interactionChoiceSetIDList is empty"
                    " and interactionLayout!=KEYBOARD");
      SendResponse(false, mobile_apis::Result::INVALID_DATA);
      return;
    }
  }

  if (!CheckChoiceIDFromRequest(
          app,
          choice_set_id_list_length,
          msg_params[strings::interaction_choice_set_id_list])) {
    LOG4CXX_ERROR(logger_,
                  "PerformInteraction has choice sets with "
                  "duplicated IDs or application does not have choice sets");
    SendResponse(false, mobile_apis::Result::INVALID_ID);
    return;
  }

  if (msg_params.keyExists(strings::vr_help)) {
    if (mobile_apis::Result::INVALID_DATA ==
        MessageHelper::VerifyImageVrHelpItems(
            msg_params[strings::vr_help], app, application_manager_)) {
      LOG4CXX_ERROR(logger_,
                    "Verification of " << strings::vr_help << " failed.");
      SendResponse(false, mobile_apis::Result::INVALID_DATA);
      return;
    }
  }

  if (IsWhiteSpaceExist()) {
    LOG4CXX_ERROR(logger_,
                  "Incoming perform interaction has contains \t\n \\t \\n");
    SendResponse(false, mobile_apis::Result::INVALID_DATA);
    return;
  }

  switch (interaction_mode_) {
    case mobile_apis::InteractionMode::BOTH: {
      LOG4CXX_DEBUG(logger_, "Interaction Mode: BOTH");
      if (!CheckChoiceSetVRSynonyms(app) || !CheckChoiceSetMenuNames(app) ||
          !CheckVrHelpItemPositions(app) ||
          !CheckChoiceSetListVRCommands(app)) {
        return;
      }
      break;
    }
    case mobile_apis::InteractionMode::MANUAL_ONLY: {
      LOG4CXX_DEBUG(logger_, "Interaction Mode: MANUAL_ONLY");
      if (!CheckChoiceSetVRSynonyms(app) || !CheckChoiceSetMenuNames(app) ||
          !CheckVrHelpItemPositions(app)) {
        return;
      }
      break;
    }
    case mobile_apis::InteractionMode::VR_ONLY: {
      LOG4CXX_DEBUG(logger_, "Interaction Mode: VR_ONLY");
      if (!CheckChoiceSetVRSynonyms(app) || !CheckVrHelpItemPositions(app) ||
          !CheckChoiceSetListVRCommands(app)) {
        return;
      }
      break;
    }
    default: {
      LOG4CXX_ERROR(logger_, "Unknown interaction mode");
      return;
    }
  }

  app->set_perform_interaction_mode(static_cast<int32_t>(interaction_mode_));
  app->set_perform_interaction_active(true);
  app->set_perform_interaction_layout(interaction_layout);
  // increment amount of active requests
  ++pi_requests_count_;
  SendVRPerformInteractionRequest(app);
  SendUIPerformInteractionRequest(app);
}

void PerformInteractionRequest::on_event(const event_engine::Event& event) {
  LOG4CXX_AUTO_TRACE(logger_);
  const smart_objects::SmartObject& message = event.smart_object();
  smart_objects::SmartObject msg_param =
      smart_objects::SmartObject(smart_objects::SmartType_Map);

  switch (event.id()) {
    case hmi_apis::FunctionID::UI_OnResetTimeout: {
      LOG4CXX_DEBUG(logger_, "Received UI_OnResetTimeout event");
      application_manager_.updateRequestTimeout(
          connection_key(), correlation_id(), default_timeout());
      break;
    }
    case hmi_apis::FunctionID::UI_PerformInteraction: {
      LOG4CXX_DEBUG(logger_, "Received UI_PerformInteraction event");
      EndAwaitForInterface(HmiInterfaces::HMI_INTERFACE_UI);
      ui_response_received_ = true;

      if (FirstAnsweredInterface::NONE == first_responder_) {
        first_responder_ = FirstAnsweredInterface::UI;
      }

      unsubscribe_from_event(hmi_apis::FunctionID::UI_PerformInteraction);
      ui_result_code_ = static_cast<hmi_apis::Common_Result::eType>(
          message[strings::params][hmi_response::code].asUInt());
      GetInfo(message, ui_info_);
      ProcessUIResponse(event.smart_object(), msg_param);
      break;
    }
    case hmi_apis::FunctionID::VR_PerformInteraction: {
      LOG4CXX_DEBUG(logger_, "Received VR_PerformInteraction");
      EndAwaitForInterface(HmiInterfaces::HMI_INTERFACE_VR);
      vr_response_received_ = true;

      if (FirstAnsweredInterface::NONE == first_responder_) {
        first_responder_ = FirstAnsweredInterface::VR;
      }

      unsubscribe_from_event(hmi_apis::FunctionID::VR_PerformInteraction);
      vr_result_code_ = static_cast<hmi_apis::Common_Result::eType>(
          message[strings::params][hmi_response::code].asUInt());
      GetInfo(message, vr_info_);
      const bool response_process_result =
          ProcessVRResponse(event.smart_object(), msg_param);
      vr_params_ = msg_param;
      if (response_process_result) {
        return;
      }
      break;
    }
    default: {
      LOG4CXX_ERROR(logger_, "Received unknown event" << event.id());
      break;
    }
  }

  if (!HasHMIResponsesToWait()) {
    LOG4CXX_DEBUG(logger_, "Send response in BOTH iteraction mode");
    const bool send_vr_params_only =
        (FirstAnsweredInterface::VR == first_responder_ &&
         mobile_apis::InteractionMode::VR_ONLY == interaction_mode_);

    if (send_vr_params_only) {
      SetChoiceIdToResponseMsgParams(vr_params_);
      SendBothModeResponse(vr_params_);
    } else {
      SetChoiceIdToResponseMsgParams(msg_param);
      SendBothModeResponse(msg_param);
    }
    first_responder_ = FirstAnsweredInterface::NONE;
  }
}

void PerformInteractionRequest::onTimeOut() {
  LOG4CXX_AUTO_TRACE(logger_);

  switch (interaction_mode_) {
    case mobile_apis::InteractionMode::BOTH: {
      LOG4CXX_DEBUG(logger_, "Interaction Mode: BOTH");
      if (true == vr_response_received_) {
        unsubscribe_from_event(hmi_apis::FunctionID::UI_PerformInteraction);
        DisablePerformInteraction();
        CommandRequestImpl::onTimeOut();
      } else {
        application_manager_.updateRequestTimeout(
            connection_key(), correlation_id(), default_timeout_);
      }
      break;
    }
    case mobile_apis::InteractionMode::VR_ONLY: {
      LOG4CXX_DEBUG(logger_, "Interaction Mode: VR_ONLY");
      unsubscribe_from_event(hmi_apis::FunctionID::UI_PerformInteraction);
      DisablePerformInteraction();
      CommandRequestImpl::onTimeOut();
      break;
    }
    case mobile_apis::InteractionMode::MANUAL_ONLY: {
      LOG4CXX_DEBUG(logger_, "InteractionMode: MANUAL_ONLY");
      unsubscribe_from_event(hmi_apis::FunctionID::UI_PerformInteraction);
      DisablePerformInteraction();
      CommandRequestImpl::onTimeOut();
      break;
    }
    default: {
      LOG4CXX_ERROR(logger_, "INVALID ENUM");
      return;
    }
  };
}

bool PerformInteractionRequest::ProcessVRResponse(
    const smart_objects::SmartObject& message,
    smart_objects::SmartObject& msg_params) {
  LOG4CXX_AUTO_TRACE(logger_);
  using namespace hmi_apis;
  using namespace mobile_apis;
  using namespace smart_objects;
  using namespace helpers;

  ApplicationSharedPtr app = application_manager_.application(connection_key());

  if (!app) {
    LOG4CXX_ERROR(logger_, "NULL pointer");
    return false;
  }

  msg_params[strings::trigger_source] =
      static_cast<int32_t>(TriggerSource::TS_VR);

  const bool is_vr_aborted_timeout = Compare<Common_Result::eType, EQ, ONE>(
      vr_result_code_, Common_Result::ABORTED, Common_Result::TIMED_OUT);

  if (is_vr_aborted_timeout) {
    LOG4CXX_DEBUG(logger_, "VR response aborted");
    if (InteractionMode::VR_ONLY == interaction_mode_) {
      LOG4CXX_DEBUG(logger_, "Aborted or Timeout Send Close Popup");
      TerminatePerformInteraction();
      SendResponse(false, MessageHelper::HMIToMobileResult(vr_result_code_));
      return true;
    }
    LOG4CXX_DEBUG(logger_, "Update timeout for UI");
    application_manager_.updateRequestTimeout(
        connection_key(), correlation_id(), default_timeout_);
    return false;
  }

  if (FirstAnsweredInterface::VR == first_responder_) {
    // After VR.PerformInteraction response HMI should close UI popup window
    // if UI.PerformInteraction response comes
    // after VR.PerformInteraction response.
    // In this case SDL should send UI_ClosePopUp request.
    const std::string method_name = "UI.PerformInteraction";
    smart_objects::SmartObject hmi_request_params =
        smart_objects::SmartObject(smart_objects::SmartType_Map);
    hmi_request_params[hmi_request::method_name] = method_name;
    SendHMIRequest(hmi_apis::FunctionID::UI_ClosePopUp, &hmi_request_params);
  }

  const SmartObject& hmi_msg_params = message[strings::msg_params];
  if (hmi_msg_params.keyExists(strings::choice_id)) {
    const int choice_id = hmi_msg_params[strings::choice_id].asInt();
    if (!CheckChoiceIDFromResponse(app, choice_id)) {
      LOG4CXX_ERROR(logger_, "Wrong choiceID was received from HMI");
      TerminatePerformInteraction();
      SendResponse(
          false, Result::GENERIC_ERROR, "Wrong choiceID was received from HMI");
      return true;
    }
    vr_choice_id_received_ = choice_id;
  }

  if (mobile_apis::InteractionMode::BOTH == interaction_mode_ ||
      mobile_apis::InteractionMode::MANUAL_ONLY == interaction_mode_) {
    LOG4CXX_DEBUG(logger_, "Update timeout for UI");
    application_manager_.updateRequestTimeout(
        connection_key(), correlation_id(), default_timeout_);
  }

  const bool is_vr_result_success = Compare<Common_Result::eType, EQ, ONE>(
      vr_result_code_, Common_Result::SUCCESS, Common_Result::WARNINGS);

  if (is_vr_result_success &&
      InteractionMode::MANUAL_ONLY == interaction_mode_) {
    LOG4CXX_DEBUG(logger_,
                  "VR response is successfull in MANUAL_ONLY mode "
                      << "Wait for UI response");
    // in case MANUAL_ONLY mode VR.PI SUCCESS just return
    return false;
  }

  return false;
}

void PerformInteractionRequest::ProcessUIResponse(
    const smart_objects::SmartObject& message,
    smart_objects::SmartObject& msg_params) {
  LOG4CXX_AUTO_TRACE(logger_);
  using namespace helpers;
  using namespace smart_objects;

  ApplicationSharedPtr app = application_manager_.application(connection_key());
  if (!app) {
    LOG4CXX_ERROR(logger_, "NULL pointer");
    return;
  }

  HmiInterfaces::InterfaceState ui_interface_state =
      application_manager_.hmi_interfaces().GetInterfaceState(
          HmiInterfaces::HMI_INTERFACE_UI);

  bool result = Compare<hmi_apis::Common_Result::eType, EQ, ONE>(
      ui_result_code_,
      hmi_apis::Common_Result::SUCCESS,
      hmi_apis::Common_Result::WARNINGS);

  result = result ||
           (hmi_apis::Common_Result::UNSUPPORTED_RESOURCE == ui_result_code_ &&
            HmiInterfaces::STATE_NOT_AVAILABLE != ui_interface_state);

  const bool is_pi_warning = Compare<hmi_apis::Common_Result::eType, EQ, ONE>(
      ui_result_code_, hmi_apis::Common_Result::WARNINGS);

  const bool is_pi_unsupported =
      Compare<hmi_apis::Common_Result::eType, EQ, ONE>(
          ui_result_code_, hmi_apis::Common_Result::UNSUPPORTED_RESOURCE);

  if (result) {
    if (is_pi_unsupported) {
      ui_result_code_ = hmi_apis::Common_Result::UNSUPPORTED_RESOURCE;
      ui_info_ = message[strings::msg_params][strings::info].asString();
    } else {
      if (message.keyExists(strings::msg_params)) {
        msg_params = message[strings::msg_params];
      }
      if (is_pi_warning) {
        ui_result_code_ = hmi_apis::Common_Result::WARNINGS;
        ui_info_ = message[strings::msg_params][strings::info].asString();
      }
    }

    // result code must be GENERIC_ERROR in case wrong choice_id
    if (msg_params.keyExists(strings::choice_id)) {
      const std::int32_t ui_choise_id =
          static_cast<std::int32_t>(msg_params[strings::choice_id].asInt());

      if (!CheckChoiceIDFromResponse(app, ui_choise_id)) {
        ui_result_code_ = hmi_apis::Common_Result::GENERIC_ERROR;
        ui_info_ = "Wrong choiceID was received from HMI";
      } else {
        ui_choice_id_received_ = ui_choise_id;
        msg_params[strings::trigger_source] =
            mobile_apis::TriggerSource::TS_MENU;
      }
    } else if (msg_params.keyExists(strings::manual_text_entry)) {
      msg_params[strings::trigger_source] =
          mobile_apis::TriggerSource::TS_KEYBOARD;
      if (msg_params[strings::manual_text_entry].empty()) {
        msg_params.erase(strings::manual_text_entry);
      }
    }
  }
}

void PerformInteractionRequest::SendUIPerformInteractionRequest(
    application_manager::ApplicationSharedPtr const app) {
  LOG4CXX_AUTO_TRACE(logger_);
  smart_objects::SmartObject& choice_set_id_list =
      (*message_)[strings::msg_params][strings::interaction_choice_set_id_list];

  smart_objects::SmartObject msg_params =
      smart_objects::SmartObject(smart_objects::SmartType_Map);

  if ((*message_)[strings::msg_params].keyExists(strings::cancel_id)) {
    msg_params[strings::cancel_id] =
        (*message_)[strings::msg_params][strings::cancel_id].asInt();
  }

  mobile_apis::InteractionMode::eType mode =
      static_cast<mobile_apis::InteractionMode::eType>(
          (*message_)[strings::msg_params][strings::interaction_mode].asInt());

  if (mobile_apis::InteractionMode::VR_ONLY != mode) {
    msg_params[hmi_request::initial_text][hmi_request::field_name] =
        static_cast<int32_t>(
            hmi_apis::Common_TextFieldName::initialInteractionText);
    msg_params[hmi_request::initial_text][hmi_request::field_text] =
        (*message_)[strings::msg_params][hmi_request::initial_text];
  }
  bool is_vr_help_item = false;
  if (mobile_apis::InteractionMode::MANUAL_ONLY != mode) {
    msg_params[strings::vr_help_title] =
        (*message_)[strings::msg_params][strings::initial_text].asString();
    if ((*message_)[strings::msg_params].keyExists(strings::vr_help)) {
      is_vr_help_item = true;
      msg_params[strings::vr_help] =
          (*message_)[strings::msg_params][strings::vr_help];
    }
  }

  msg_params[strings::timeout] =
      (*message_)[strings::msg_params][strings::timeout].asUInt();
  msg_params[strings::app_id] = app->app_id();
  if (mobile_apis::InteractionMode::VR_ONLY != mode) {
    msg_params[strings::choice_set] =
        smart_objects::SmartObject(smart_objects::SmartType_Array);
  }
  int32_t index_array_of_vr_help = 0;
  for (size_t i = 0; i < choice_set_id_list.length(); ++i) {
    smart_objects::SmartObject* choice_set =
        app->FindChoiceSet(choice_set_id_list[i].asInt());
    if (choice_set) {
      // save perform interaction choice set
      app->AddPerformInteractionChoiceSet(
          correlation_id(), choice_set_id_list[i].asInt(), *choice_set);
      for (size_t j = 0; j < (*choice_set)[strings::choice_set].length(); ++j) {
        if (mobile_apis::InteractionMode::VR_ONLY != mode) {
          size_t index = msg_params[strings::choice_set].length();
          msg_params[strings::choice_set][index] =
              (*choice_set)[strings::choice_set][j];
          // vrCommands should be added via VR.AddCommand only
          msg_params[strings::choice_set][index].erase(strings::vr_commands);
        }
        if (mobile_apis::InteractionMode::MANUAL_ONLY != mode &&
            !is_vr_help_item) {
          smart_objects::SmartObject& vr_commands =
              (*choice_set)[strings::choice_set][j][strings::vr_commands];
          if (0 < vr_commands.length()) {
            // copy only first synonym
            smart_objects::SmartObject item(smart_objects::SmartType_Map);
            item[strings::text] = vr_commands[0].asString();
            item[strings::position] = index_array_of_vr_help + 1;
            msg_params[strings::vr_help][index_array_of_vr_help++] = item;
          }
        }
      }
    }
  }
  if ((*message_)[strings::msg_params].keyExists(
          hmi_request::interaction_layout) &&
      mobile_apis::InteractionMode::VR_ONLY != mode) {
    msg_params[hmi_request::interaction_layout] =
        (*message_)[strings::msg_params][hmi_request::interaction_layout]
            .asInt();
  }
  StartAwaitForInterface(HmiInterfaces::HMI_INTERFACE_UI);
  SendHMIRequest(
      hmi_apis::FunctionID::UI_PerformInteraction, &msg_params, true);
}

void PerformInteractionRequest::SendVRPerformInteractionRequest(
    application_manager::ApplicationSharedPtr const app) {
  LOG4CXX_AUTO_TRACE(logger_);

  smart_objects::SmartObject msg_params =
      smart_objects::SmartObject(smart_objects::SmartType_Map);

  if ((*message_)[strings::msg_params].keyExists(strings::cancel_id)) {
    msg_params[strings::cancel_id] =
        (*message_)[strings::msg_params][strings::cancel_id].asInt();
  }

  smart_objects::SmartObject& choice_list =
      (*message_)[strings::msg_params][strings::interaction_choice_set_id_list];

  if (mobile_apis::InteractionMode::MANUAL_ONLY != interaction_mode_) {
    msg_params[strings::grammar_id] =
        smart_objects::SmartObject(smart_objects::SmartType_Array);

    int32_t grammar_id_index = 0;
    for (uint32_t i = 0; i < choice_list.length(); ++i) {
      smart_objects::SmartObject* choice_set =
          app->FindChoiceSet(choice_list[i].asInt());
      if (!choice_set) {
        LOG4CXX_WARN(logger_, "Couldn't found choiceset");
        continue;
      }
      msg_params[strings::grammar_id][grammar_id_index++] =
          (*choice_set)[strings::grammar_id].asUInt();
    }
  }

  std::vector<std::string> invalid_params;
  if ((*message_)[strings::msg_params].keyExists(strings::help_prompt)) {
    smart_objects::SmartObject& help_prompt =
        (*message_)[strings::msg_params][strings::help_prompt];
    mobile_apis::Result::eType verification_result =
        MessageHelper::VerifyTtsFiles(help_prompt, app, application_manager_);

    if (mobile_apis::Result::FILE_NOT_FOUND == verification_result) {
      LOG4CXX_WARN(
          logger_,
          "MessageHelper::VerifyTtsFiles return " << verification_result);
      invalid_params.push_back("help_prompt");
    } else {
      msg_params[strings::help_prompt] = help_prompt;
    }
  } else {
    if (choice_list.length() != 0) {
      msg_params[strings::help_prompt] =
          smart_objects::SmartObject(smart_objects::SmartType_Array);
    }
    int32_t index = 0;
    for (uint32_t i = 0; i < choice_list.length(); ++i) {
      smart_objects::SmartObject* choice_set =
          app->FindChoiceSet(choice_list[i].asInt());

      if (choice_set) {
        for (uint32_t j = 0; j < (*choice_set)[strings::choice_set].length();
             ++j) {
          smart_objects::SmartObject& vr_commands =
              (*choice_set)[strings::choice_set][j][strings::vr_commands];
          if (0 < vr_commands.length()) {
            // copy only first synonym
            smart_objects::SmartObject item(smart_objects::SmartType_Map);
            // Since there is no custom data from application side, SDL should
            // construct prompt and append delimiter to each item
            item[strings::type] = hmi_apis::Common_SpeechCapabilities::SC_TEXT;
            item[strings::text] =
                vr_commands[0].asString() +
                application_manager_.get_settings().tts_delimiter();
            msg_params[strings::help_prompt][index++] = item;
          }
        }
      } else {
        LOG4CXX_ERROR(logger_, "Can't found choiceSet!");
      }
    }
  }

  if ((*message_)[strings::msg_params].keyExists(strings::timeout_prompt)) {
    smart_objects::SmartObject& timeout_prompt =
        (*message_)[strings::msg_params][strings::timeout_prompt];
    mobile_apis::Result::eType verification_result =
        MessageHelper::VerifyTtsFiles(
            timeout_prompt, app, application_manager_);

    if (mobile_apis::Result::FILE_NOT_FOUND == verification_result) {
      LOG4CXX_WARN(
          logger_,
          "MessageHelper::VerifyTtsFiles return " << verification_result);
      invalid_params.push_back("timeout_prompt");
    } else {
      msg_params[strings::timeout_prompt] = timeout_prompt;
    }
  } else {
    if (msg_params.keyExists(strings::help_prompt)) {
      msg_params[strings::timeout_prompt] = msg_params[strings::help_prompt];
    }
  }

  if ((*message_)[strings::msg_params].keyExists(strings::initial_prompt)) {
    smart_objects::SmartObject& initial_prompt =
        (*message_)[strings::msg_params][strings::initial_prompt];
    mobile_apis::Result::eType verification_result =
        MessageHelper::VerifyTtsFiles(
            initial_prompt, app, application_manager_);

    if (mobile_apis::Result::FILE_NOT_FOUND == verification_result) {
      LOG4CXX_WARN(
          logger_,
          "MessageHelper::VerifyTtsFiles return " << verification_result);
      invalid_params.push_back("initial_prompt");
    } else {
      msg_params[strings::initial_prompt] = initial_prompt;
    }
  }

  if (!invalid_params.empty()) {
    const std::string params_list =
        std::accumulate(std::begin(invalid_params),
                        std::end(invalid_params),
                        std::string(""),
                        [](std::string& first, std::string& second) {
                          return first.empty() ? second : first + ", " + second;
                        });
    const std::string info =
        "One or more files needed for " + params_list + " are not present";
    SendResponse(false, mobile_apis::Result::FILE_NOT_FOUND, info.c_str());
    return;
  }

  msg_params[strings::timeout] =
      (*message_)[strings::msg_params][strings::timeout].asUInt();
  ;
  msg_params[strings::app_id] = app->app_id();
  StartAwaitForInterface(HmiInterfaces::HMI_INTERFACE_VR);
  SendHMIRequest(
      hmi_apis::FunctionID::VR_PerformInteraction, &msg_params, true);
}

bool PerformInteractionRequest::CheckChoiceSetMenuNames(
    application_manager::ApplicationSharedPtr const app) {
  LOG4CXX_AUTO_TRACE(logger_);

  smart_objects::SmartObject& choice_list =
      (*message_)[strings::msg_params][strings::interaction_choice_set_id_list];

  for (size_t i = 0; i < choice_list.length(); ++i) {
    // choice_set contains SmartObject msg_params
    smart_objects::SmartObject* i_choice_set =
        app->FindChoiceSet(choice_list[i].asInt());

    for (size_t j = 0; j < choice_list.length(); ++j) {
      smart_objects::SmartObject* j_choice_set =
          app->FindChoiceSet(choice_list[j].asInt());

      if (i == j) {
        // skip check the same element
        continue;
      }

      if (!i_choice_set || !j_choice_set) {
        LOG4CXX_ERROR(logger_, "Invalid ID");
        SendResponse(false, mobile_apis::Result::INVALID_ID);
        return false;
      }

      size_t ii = 0;
      size_t jj = 0;
      for (; ii < (*i_choice_set)[strings::choice_set].length(); ++ii) {
        for (; jj < (*j_choice_set)[strings::choice_set].length(); ++jj) {
          const std::string& ii_menu_name =
              (*i_choice_set)[strings::choice_set][ii][strings::menu_name]
                  .asString();
          const std::string& jj_menu_name =
              (*j_choice_set)[strings::choice_set][jj][strings::menu_name]
                  .asString();

          if (ii_menu_name == jj_menu_name) {
            LOG4CXX_ERROR(logger_, "Choice set has duplicated menu name");
            SendResponse(false,
                         mobile_apis::Result::DUPLICATE_NAME,
                         "Choice set has duplicated menu name");
            return false;
          }
        }
      }
    }
  }

  return true;
}

bool PerformInteractionRequest::CheckChoiceSetVRSynonyms(
    application_manager::ApplicationSharedPtr const app) {
  LOG4CXX_AUTO_TRACE(logger_);

  smart_objects::SmartObject& choice_list =
      (*message_)[strings::msg_params][strings::interaction_choice_set_id_list];

  for (size_t i = 0; i < choice_list.length(); ++i) {
    // choice_set contains SmartObject msg_params
    smart_objects::SmartObject* i_choice_set =
        app->FindChoiceSet(choice_list[i].asInt());

    for (size_t j = 0; j < choice_list.length(); ++j) {
      smart_objects::SmartObject* j_choice_set =
          app->FindChoiceSet(choice_list[j].asInt());

      if (i == j) {
        // skip check the same element
        continue;
      }

      if ((!i_choice_set) || (!j_choice_set)) {
        LOG4CXX_ERROR(logger_, "Invalid ID");
        SendResponse(false, mobile_apis::Result::INVALID_ID);
        return false;
      }

      size_t ii = 0;
      size_t jj = 0;
      for (; ii < (*i_choice_set)[strings::choice_set].length(); ++ii) {
        for (; jj < (*j_choice_set)[strings::choice_set].length(); ++jj) {
          if (!((*i_choice_set)[strings::choice_set][ii].keyExists(
                    strings::vr_commands) &&
                (*j_choice_set)[strings::choice_set][jj].keyExists(
                    strings::vr_commands))) {
            LOG4CXX_DEBUG(logger_,
                          "One or both sets has missing vr commands, skipping "
                          "synonym check");
            return true;
          }
          // choice_set pointer contains SmartObject msg_params
          smart_objects::SmartObject& ii_vr_commands =
              (*i_choice_set)[strings::choice_set][ii][strings::vr_commands];

          smart_objects::SmartObject& jj_vr_commands =
              (*j_choice_set)[strings::choice_set][jj][strings::vr_commands];

          for (size_t iii = 0; iii < ii_vr_commands.length(); ++iii) {
            for (size_t jjj = 0; jjj < jj_vr_commands.length(); ++jjj) {
              const custom_str::CustomString& vr_cmd_i =
                  ii_vr_commands[iii].asCustomString();
              const custom_str::CustomString& vr_cmd_j =
                  jj_vr_commands[jjj].asCustomString();
              if (vr_cmd_i.CompareIgnoreCase(vr_cmd_j)) {
                LOG4CXX_ERROR(logger_, "Choice set has duplicated VR synonym");
                SendResponse(false,
                             mobile_apis::Result::DUPLICATE_NAME,
                             "Choice set has duplicated VR synonym");
                return false;
              }
            }
          }
        }
      }
    }
  }
  return true;
}

bool PerformInteractionRequest::CheckVrHelpItemPositions(
    application_manager::ApplicationSharedPtr const app) {
  LOG4CXX_AUTO_TRACE(logger_);

  if (!(*message_)[strings::msg_params].keyExists(strings::vr_help)) {
    LOG4CXX_DEBUG(logger_, strings::vr_help << " is omitted.");
    return true;
  }

  smart_objects::SmartObject& vr_help =
      (*message_)[strings::msg_params][strings::vr_help];

  int32_t position = 1;
  for (size_t i = 0; i < vr_help.length(); ++i) {
    if (position != vr_help[i][strings::position].asInt()) {
      LOG4CXX_ERROR(logger_, "Non-sequential vrHelp item position");
      SendResponse(false,
                   mobile_apis::Result::REJECTED,
                   "Non-sequential vrHelp item position");
      return false;
    }
    ++position;
  }
  return true;
}

void PerformInteractionRequest::DisablePerformInteraction() {
  LOG4CXX_AUTO_TRACE(logger_);

  ApplicationSharedPtr app = application_manager_.application(connection_key());
  if (!app) {
    LOG4CXX_ERROR(logger_, "NULL pointer");
    return;
  }

  if (app->is_perform_interaction_active()) {
    // decrease amount of active requests
    --pi_requests_count_;
    if (!pi_requests_count_) {
      app->set_perform_interaction_active(false);
      app->set_perform_interaction_mode(-1);
    }
  }
  app->DeletePerformInteractionChoiceSet(correlation_id());
}

bool PerformInteractionRequest::IsWhiteSpaceExist() {
  LOG4CXX_AUTO_TRACE(logger_);
  const char* str = NULL;

  str = (*message_)[strings::msg_params][strings::initial_text].asCharArray();
  if (!CheckSyntax(str)) {
    LOG4CXX_ERROR(logger_, "Invalid initial_text syntax check failed");
    return true;
  }

  if ((*message_)[strings::msg_params].keyExists(strings::initial_prompt)) {
    const smart_objects::SmartArray* ip_array =
        (*message_)[strings::msg_params][strings::initial_prompt].asArray();

    smart_objects::SmartArray::const_iterator it_ip = ip_array->begin();
    smart_objects::SmartArray::const_iterator it_ip_end = ip_array->end();

    for (; it_ip != it_ip_end; ++it_ip) {
      str = (*it_ip)[strings::text].asCharArray();
      if (strlen(str) && !CheckSyntax(str)) {
        LOG4CXX_ERROR(logger_, "Invalid initial_prompt syntax check failed");
        return true;
      }
    }
  }

  if ((*message_)[strings::msg_params].keyExists(strings::help_prompt)) {
    const smart_objects::SmartArray* hp_array =
        (*message_)[strings::msg_params][strings::help_prompt].asArray();

    smart_objects::SmartArray::const_iterator it_hp = hp_array->begin();
    smart_objects::SmartArray::const_iterator it_hp_end = hp_array->end();

    for (; it_hp != it_hp_end; ++it_hp) {
      str = (*it_hp)[strings::text].asCharArray();
      if (strlen(str) && !CheckSyntax(str)) {
        LOG4CXX_ERROR(logger_, "Invalid help_prompt syntax check failed");
        return true;
      }
    }
  }

  if ((*message_)[strings::msg_params].keyExists(strings::timeout_prompt)) {
    const smart_objects::SmartArray* tp_array =
        (*message_)[strings::msg_params][strings::timeout_prompt].asArray();

    smart_objects::SmartArray::const_iterator it_tp = tp_array->begin();
    smart_objects::SmartArray::const_iterator it_tp_end = tp_array->end();

    for (; it_tp != it_tp_end; ++it_tp) {
      str = (*it_tp)[strings::text].asCharArray();
      if (strlen(str) && !CheckSyntax(str)) {
        LOG4CXX_ERROR(logger_, "Invalid timeout_prompt syntax check failed");
        return true;
      }
    }
  }

  if ((*message_)[strings::msg_params].keyExists(strings::vr_help)) {
    const smart_objects::SmartArray* vh_array =
        (*message_)[strings::msg_params][strings::vr_help].asArray();

    smart_objects::SmartArray::const_iterator it_vh = vh_array->begin();
    smart_objects::SmartArray::const_iterator it_vh_end = vh_array->end();

    for (; it_vh != it_vh_end; ++it_vh) {
      str = (*it_vh)[strings::text].asCharArray();
      if (!CheckSyntax(str)) {
        LOG4CXX_ERROR(logger_, "Invalid vr_help syntax check failed");
        return true;
      }

      if ((*it_vh).keyExists(strings::image)) {
        str = (*it_vh)[strings::image][strings::value].asCharArray();
        if (!CheckSyntax(str)) {
          LOG4CXX_ERROR(logger_,
                        "Invalid vr_help image value syntax check failed");
          return true;
        }
      }
    }
  }
  return false;
}

void PerformInteractionRequest::TerminatePerformInteraction() {
  LOG4CXX_AUTO_TRACE(logger_);

  smart_objects::SmartObject msg_params =
      smart_objects::SmartObject(smart_objects::SmartType_Map);
  msg_params[hmi_request::method_name] = "UI.PerformInteraction";
  SendHMIRequest(hmi_apis::FunctionID::UI_ClosePopUp, &msg_params);
  DisablePerformInteraction();
}

bool PerformInteractionRequest::CheckChoiceIDFromResponse(
    ApplicationSharedPtr app, const int32_t choice_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  const DataAccessor<PerformChoiceSetMap> accessor =
      app->performinteraction_choice_set_map();
  const PerformChoiceSetMap& choice_set_map = accessor.GetData();

  PerformChoiceSetMap::const_iterator choice_set_map_it =
      choice_set_map.find(correlation_id());
  if (choice_set_map.end() != choice_set_map_it) {
    const PerformChoice& choice = choice_set_map_it->second;
    PerformChoice::const_iterator it = choice.begin();
    for (; choice.end() != it; ++it) {
      if ((*it->second).keyExists(strings::choice_set)) {
        const smart_objects::SmartObject& choice_set =
            (*it->second).getElement(strings::choice_set);
        for (size_t j = 0; j < choice_set.length(); ++j) {
          if (choice_id ==
              choice_set.getElement(j).getElement(strings::choice_id).asInt()) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

bool PerformInteractionRequest::CheckChoiceSetListVRCommands(
    ApplicationSharedPtr app) {
  LOG4CXX_AUTO_TRACE(logger_);

  const smart_objects::SmartObject& choice_set_id_list =
      (*message_)[strings::msg_params][strings::interaction_choice_set_id_list];

  smart_objects::SmartObject* choice_set = nullptr;

  for (size_t i = 0; i < choice_set_id_list.length(); ++i) {
    choice_set = app->FindChoiceSet(choice_set_id_list[i].asInt());

    // this should never ever happen since this was already checked
    if (choice_set == nullptr) {
      LOG4CXX_ERROR(
          logger_,
          "Couldn't find choiceset_id = " << choice_set_id_list[i].asInt());
      SendResponse(false, mobile_apis::Result::INVALID_ID);
      return false;
    }

    const smart_objects::SmartObject& choices_list =
        (*choice_set)[strings::choice_set];
    auto vr_status = MessageHelper::CheckChoiceSetVRCommands(choices_list);

    // if not all choices have vr commands
    if (vr_status != MessageHelper::ChoiceSetVRCommandsStatus::ALL) {
      LOG4CXX_ERROR(logger_,
                    "PerformInteraction has choice sets with "
                    "missing vrCommands, not in MANUAL_ONLY mode");
      SendResponse(false,
                   mobile_apis::Result::INVALID_DATA,
                   "Some choices don't contain VR commands.");
      return false;
    }
  }
  return true;
}

bool PerformInteractionRequest::CheckChoiceIDFromRequest(
    ApplicationSharedPtr app,
    const size_t choice_set_id_list_length,
    const smart_objects::SmartObject& choice_set_id_list) const {
  LOG4CXX_AUTO_TRACE(logger_);

  size_t choice_list_length = 0;
  std::set<uint32_t> choice_id_set;
  smart_objects::SmartObject* choice_set = 0;
  std::pair<std::set<uint32_t>::iterator, bool> ins_res;

  for (size_t i = 0; i < choice_set_id_list_length; ++i) {
    choice_set = app->FindChoiceSet(choice_set_id_list[i].asInt());
    if (!choice_set) {
      LOG4CXX_ERROR(
          logger_,
          "Couldn't find choiceset_id = " << choice_set_id_list[i].asInt());
      return false;
    }

    choice_list_length = (*choice_set)[strings::choice_set].length();
    const smart_objects::SmartObject& choices_list =
        (*choice_set)[strings::choice_set];
    for (size_t k = 0; k < choice_list_length; ++k) {
      ins_res =
          choice_id_set.insert(choices_list[k][strings::choice_id].asInt());
      if (!ins_res.second) {
        LOG4CXX_ERROR(logger_,
                      "choice with ID "
                          << choices_list[k][strings::choice_id].asInt()
                          << " already exists");
        return false;
      }
    }
  }
  return true;
}

const bool PerformInteractionRequest::HasHMIResponsesToWait() const {
  LOG4CXX_AUTO_TRACE(logger_);
  return !ui_response_received_ || !vr_response_received_;
}

void PerformInteractionRequest::SendBothModeResponse(
    const smart_objects::SmartObject& msg_param) {
  LOG4CXX_AUTO_TRACE(logger_);
  mobile_apis::Result::eType perform_interaction_result_code =
      mobile_apis::Result::INVALID_ENUM;
  app_mngr::commands::ResponseInfo ui_perform_info(
      ui_result_code_, HmiInterfaces::HMI_INTERFACE_UI, application_manager_);
  app_mngr::commands::ResponseInfo vr_perform_info(
      vr_result_code_, HmiInterfaces::HMI_INTERFACE_VR, application_manager_);
  const bool result =
      PrepareResultForMobileResponse(ui_perform_info, vr_perform_info);
  perform_interaction_result_code =
      PrepareResultCodeForResponse(ui_perform_info, vr_perform_info);
  const smart_objects::SmartObject* response_params =
      msg_param.empty() ? NULL : &msg_param;
  std::string info = app_mngr::commands::MergeInfos(
      ui_perform_info, ui_info_, vr_perform_info, vr_info_);

  DisablePerformInteraction();

  SendResponse(result,
               perform_interaction_result_code,
               info.empty() ? NULL : info.c_str(),
               response_params);
}

mobile_apis::Result::eType
PerformInteractionRequest::PrepareResultCodeForResponse(
    const app_mngr::commands::ResponseInfo& ui_response,
    const app_mngr::commands::ResponseInfo& vr_response) {
  LOG4CXX_DEBUG(logger_,
                "InteractionMode = " << static_cast<int32_t>(interaction_mode_)
                                     << " | FirstAnsweredInterface = "
                                     << static_cast<int32_t>(first_responder_));

  if (mobile_apis::InteractionMode::VR_ONLY == interaction_mode_) {
    if (FirstAnsweredInterface::VR == first_responder_) {
      return MessageHelper::HMIToMobileResult(vr_result_code_);
    }
  }

  if (mobile_apis::InteractionMode::BOTH == interaction_mode_) {
    if (IsVRPerformInteractionResponseSuccessfulInBothMode()) {
      return MessageHelper::HMIToMobileResult(vr_result_code_);
    }
    return MessageHelper::HMIToMobileResult(ui_result_code_);
  }

  return CommandRequestImpl::PrepareResultCodeForResponse(ui_response,
                                                          vr_response);
}

bool PerformInteractionRequest::PrepareResultForMobileResponse(
    app_mngr::commands::ResponseInfo& ui_response,
    app_mngr::commands::ResponseInfo& vr_response) const {
  if (mobile_apis::InteractionMode::VR_ONLY == interaction_mode_) {
    if (FirstAnsweredInterface::VR == first_responder_) {
      return vr_response.is_ok;
    }
  }

  if (mobile_apis::InteractionMode::BOTH == interaction_mode_) {
    return (vr_response.is_ok || ui_response.is_ok);
  }

  return CommandRequestImpl::PrepareResultForMobileResponse(ui_response,
                                                            vr_response);
}

bool PerformInteractionRequest::
    IsVRPerformInteractionResponseSuccessfulInBothMode() {
  using namespace mobile_apis;
  app_mngr::commands::ResponseInfo vr_perform_info(
      vr_result_code_, HmiInterfaces::HMI_INTERFACE_VR, application_manager_);
  return (vr_perform_info.is_ok && InteractionMode::BOTH == interaction_mode_);
}

void PerformInteractionRequest::SetChoiceIdToResponseMsgParams(
    ns_smart_device_link::ns_smart_objects::SmartObject& msg_param) {
  LOG4CXX_AUTO_TRACE(logger_);

  std::int32_t choice_id = INVALID_CHOICE_ID;

  switch (interaction_mode_) {
    case mobile_apis::InteractionMode::eType::MANUAL_ONLY: {
      if (INVALID_CHOICE_ID != ui_choice_id_received_) {
        choice_id = ui_choice_id_received_;
      }
    } break;
    case mobile_apis::InteractionMode::eType::VR_ONLY:
      if (INVALID_CHOICE_ID != vr_choice_id_received_) {
        choice_id = vr_choice_id_received_;
      }
      break;
    case mobile_apis::InteractionMode::eType::BOTH:
      choice_id = (first_responder_ == FirstAnsweredInterface::UI) &&
                          (INVALID_CHOICE_ID != ui_choice_id_received_)
                      ? ui_choice_id_received_
                      : vr_choice_id_received_;
      break;
    default:
      LOG4CXX_DEBUG(logger_, "Invalid interaction mode: " << interaction_mode_);
      return;
  }

  msg_param[strings::choice_id] = choice_id;
}

}  // namespace commands

}  // namespace sdl_rpc_plugin
