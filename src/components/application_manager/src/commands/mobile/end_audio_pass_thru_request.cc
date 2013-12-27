/*

 Copyright (c) 2013, Ford Motor Company
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

#include "application_manager/commands/mobile/end_audio_pass_thru_request.h"
#include "application_manager/application_manager_impl.h"
#include "interfaces/HMI_API.h"

namespace application_manager {

namespace commands {

EndAudioPassThruRequest::EndAudioPassThruRequest(
  const MessageSharedPtr& message)
  : CommandRequestImpl(message) {
}

EndAudioPassThruRequest::~EndAudioPassThruRequest() {
}

void EndAudioPassThruRequest::Run() {
  LOG4CXX_INFO(logger_, "EndAudioPassThruRequest::Run");
  bool ended_successfully = ApplicationManagerImpl::instance()->end_audio_pass_thru();

  if (ended_successfully) {
    SendHMIRequest(hmi_apis::FunctionID::UI_EndAudioPassThru, NULL, true);
    int session_key =
      (*message_)[strings::params][strings::connection_key].asInt();
    ApplicationManagerImpl::instance()->StopAudioPassThru(session_key);
  } else {
    SendResponse(false, mobile_apis::Result::REJECTED,
                 "No PerformAudioPassThru is now active");
  }
}

void EndAudioPassThruRequest::on_event(const event_engine::Event& event) {
  LOG4CXX_INFO(logger_, "EndAudioPassThruRequest::on_event");
  const smart_objects::SmartObject& message = event.smart_object();

  switch (event.id()) {
    case hmi_apis::FunctionID::UI_EndAudioPassThru: {
      mobile_apis::Result::eType result_code =
          static_cast<mobile_apis::Result::eType>(
              message[strings::params][hmi_response::code].asInt());

      bool result = mobile_apis::Result::SUCCESS == result_code;

      SendResponse(result, result_code, NULL, &(message[strings::msg_params]));
      break;
    }
    default: {
      LOG4CXX_ERROR(logger_, "Received unknown event" << event.id());
      return;
    }
  }
}

}  // namespace commands

}  // namespace application_manager
