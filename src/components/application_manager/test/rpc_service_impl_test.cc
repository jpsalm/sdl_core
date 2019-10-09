/*
 * Copyright (c) 2019, Ford Motor Company
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the
 * distribution.
 *
 * Neither the name of the Ford Motor Company nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <gmock/gmock.h>
#include <string>
#include "gtest/gtest.h"

#include "application_manager/rpc_service_impl.h"

#include "application_manager/commands/command.h"
#include "application_manager/mock_app_service_manager.h"
#include "application_manager/mock_application.h"
#include "application_manager/mock_application_manager.h"
#include "application_manager/mock_command_factory.h"
#include "application_manager/mock_command_holder.h"
#include "application_manager/mock_message_helper.h"
#include "application_manager/mock_request.h"
#include "application_manager/mock_request_controller_settings.h"
#include "application_manager/mock_rpc_plugin.h"
#include "application_manager/mock_rpc_plugin_manager.h"
#include "application_manager/mock_rpc_protection_manager.h"
#include "application_manager/request_controller.h"
#include "hmi_message_handler/mock_hmi_message_handler.h"
#include "include/test/protocol_handler/mock_protocol_handler.h"
#include "resumption/last_state_impl.h"

namespace test {
namespace components {
namespace application_manager_test {

namespace rpc_service = application_manager::rpc_service;
namespace am = application_manager;
using test::components::hmi_message_handler_test::MockHMIMessageHandler;
using test::components::protocol_handler_test::MockProtocolHandler;
typedef smart_objects::SmartObjectSPtr MessageSharedPtr;
using test::components::application_manager_test::MockAppServiceManager;
using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

namespace {
const uint32_t kConnectionKey = 1u;
const connection_handler::DeviceHandle kDeviceHandle = 1u;
const std::string kPolicyAppId = "policy_app_id";
const uint32_t kCorrelationId = 1u;
const uint32_t kFunctionId = 1u;
const uint32_t kAppId = 1u;
}  // namespace

class RPCServiceImplTest : public ::testing::Test {
 public:
  RPCServiceImplTest()
      : request_controller_(mock_request_controler_)
      , mock_rpc_protection_manager_(
            std::make_shared<
                testing::NiceMock<am::MockRPCProtectionManager> >())
      , mock_message_helper_(*am::MockMessageHelper::message_helper_mock())
      , last_state_("app_storage_folder", "app_info_storage")
      , mock_app_service_nmgr_(mock_app_mngr_, last_state_) {
    rpc_service_ = std::make_shared<rpc_service::RPCServiceImpl>(
        mock_app_mngr_,
        request_controller_,
        &mock_protocol_handler_,
        &mock_hmi_handler_,
        mock_command_holder_,
        mock_rpc_protection_manager_,
        hmi_so_factory_,
        mobile_so_factory_);
  }

  MessageSharedPtr CreateMessage(
      const smart_objects::SmartType type = smart_objects::SmartType_Null) {
    return std::make_shared<smart_objects::SmartObject>(type);
  }
  void PrepareBasicMessage(MessageSharedPtr& message) {
    (*message)[am::strings::params][am::strings::function_id] =
        static_cast<mobile_apis::FunctionID::eType>(
            mobile_apis::FunctionID::RESERVED);
    (*message)[am::strings::params][am::strings::correlation_id] =
        kCorrelationId;
    (*message)[am::strings::params][am::strings::protocol_type] =
        am::commands::CommandImpl::mobile_protocol_type_;
    (*message)[am::strings::params][am::strings::connection_key] =
        kConnectionKey;
  }

 protected:
  hmi_apis::HMI_API hmi_so_factory_;
  mobile_apis::MOBILE_API mobile_so_factory_;
  testing::NiceMock<MockApplicationManager> mock_app_mngr_;
  testing::NiceMock<MockRequestControlerSettings> mock_request_controler_;
  testing::NiceMock<MockProtocolHandler> mock_protocol_handler_;
  am::request_controller::RequestController request_controller_;
  testing::NiceMock<MockHMIMessageHandler> mock_hmi_handler_;
  testing::NiceMock<MockCommandHolder> mock_command_holder_;
  std::shared_ptr<am::MockRPCProtectionManager> mock_rpc_protection_manager_;
  std::shared_ptr<rpc_service::RPCService> rpc_service_;
  std::shared_ptr<MockApplication> MockAppPtr;
  am::MockMessageHelper& mock_message_helper_;
  resumption::LastStateImpl last_state_;
  MockAppServiceManager mock_app_service_nmgr_;
  testing::NiceMock<am::plugin_manager::MockRPCPluginManager>
      mock_rpc_plugin_manager_;
  testing::NiceMock<am::plugin_manager::MockRPCPlugin> mock_rpc_plugin_;
  testing::NiceMock<MockCommandFactory> mock_command_factory_;
};

TEST_F(RPCServiceImplTest, ManageMobileCommand_MessageIsNullPtr_False) {
  MessageSharedPtr message;
  ASSERT_FALSE(rpc_service_->ManageMobileCommand(
      message, am::commands::Command::CommandSource::SOURCE_MOBILE));
}

TEST_F(RPCServiceImplTest, ManageMobileCommand_IsLowVoltage_False) {
  auto message = CreateMessage();
  ON_CALL(mock_app_mngr_, IsLowVoltage()).WillByDefault(Return(true));
  ASSERT_FALSE(rpc_service_->ManageMobileCommand(
      message, am::commands::Command::CommandSource::SOURCE_MOBILE));
}

TEST_F(RPCServiceImplTest, ManageMobileCommand_AppInReconnectMode) {
  auto message = CreateMessage(smart_objects::SmartType_Map);
  auto source = am::commands::Command::CommandSource::SOURCE_MOBILE;
  (*message)[am::strings::params][am::strings::connection_key] = kConnectionKey;
  MockAppPtr = std::make_shared<NiceMock<MockApplication> >();
  ON_CALL(mock_app_mngr_, application(kConnectionKey))
      .WillByDefault(Return(MockAppPtr));
  ON_CALL(*MockAppPtr, device()).WillByDefault(Return(kDeviceHandle));
  ON_CALL(*MockAppPtr, policy_app_id()).WillByDefault(Return(kPolicyAppId));
  ON_CALL(mock_app_mngr_, IsAppInReconnectMode(kDeviceHandle, kPolicyAppId))
      .WillByDefault(Return(true));
  EXPECT_CALL(mock_command_holder_,
              Suspend(static_cast<am::ApplicationSharedPtr>(MockAppPtr),
                      am::CommandHolder::CommandType::kMobileCommand,
                      source,
                      message))
      .WillOnce(Return());
  ASSERT_TRUE(rpc_service_->ManageMobileCommand(message, source));
}

TEST_F(RPCServiceImplTest, Check) {
  // TODO
  //    auto message = CreateMessage(smart_objects::SmartType_Map);
  //    auto source = am::commands::Command::CommandSource::SOURCE_MOBILE;
  //    PrepareBasicMessage(message);
  //    auto protocol_version =
  //    protocol_handler::MajorProtocolVersion::PROTOCOL_VERSION_1;
  //    (*message)[am::strings::params][am::strings::protocol_version] =
  //    protocol_version;

  //    ON_CALL(mock_app_mngr_, application(kConnectionKey))
  //        .WillByDefault(Return(MockAppPtr));
  //    ON_CALL(mock_app_mngr_, IsAppInReconnectMode(kDeviceHandle,
  //    kPolicyAppId))
  //        .WillByDefault(Return(false));
  //    ON_CALL(mock_message_helper_,CreateNegativeResponse(_,_,_,_)).WillByDefault(Return(message));
  //    ON_CALL(mock_app_mngr_,
  //    SupportedSDLVersion()).WillByDefault(Return(protocol_version));
  //    ON_CALL(mock_app_mngr_,
  //    GetAppServiceManager()).WillByDefault(ReturnRef(mock_app_service_nmgr_));
  ////    ON_CALL(mock_app_service_nmgr_,GetRPCPassingHandler()).
  //    rpc_service_->ManageMobileCommand(message, source);
  // TODO
}

TEST_F(RPCServiceImplTest, ManageHMICommand_MessageIsNullPtr_False) {
  MessageSharedPtr message;
  ASSERT_FALSE(rpc_service_->ManageHMICommand(
      message, am::commands::Command::CommandSource::SOURCE_HMI));
}

TEST_F(RPCServiceImplTest, ManageHMICommand_IsLowVoltage_ReturnFalse) {
  auto message = CreateMessage();
  ON_CALL(mock_app_mngr_, IsLowVoltage()).WillByDefault(Return(true));
  ASSERT_FALSE(rpc_service_->ManageHMICommand(
      message, am::commands::Command::CommandSource::SOURCE_HMI));
}

TEST_F(RPCServiceImplTest, ManageHMICommand_PluginIsEmpty_False) {
  auto message = CreateMessage();
  auto source = am::commands::Command::CommandSource::SOURCE_HMI;
  (*message)[am::strings::params][am::strings::function_id] = kFunctionId;
  ON_CALL(mock_app_mngr_, IsLowVoltage()).WillByDefault(Return(false));
  ON_CALL(mock_app_mngr_, GetPluginManager())
      .WillByDefault(ReturnRef(mock_rpc_plugin_manager_));
  typedef am::plugin_manager::RPCPlugin RPCPlugin;
  utils::Optional<RPCPlugin> mock_rpc_plugin_opt(
      utils::Optional<RPCPlugin>::OptionalEmpty::EMPTY);
  ON_CALL(mock_rpc_plugin_manager_, FindPluginToProcess(kFunctionId, source))
      .WillByDefault(Return(mock_rpc_plugin_opt));
  ASSERT_FALSE(rpc_service_->ManageHMICommand(message, source));
}

TEST_F(RPCServiceImplTest, ManageHMICommand_FailedCreateCommand_False) {
  auto message = CreateMessage();
  auto source = am::commands::Command::CommandSource::SOURCE_HMI;
  (*message)[am::strings::params][am::strings::function_id] = kFunctionId;
  ON_CALL(mock_app_mngr_, IsLowVoltage()).WillByDefault(Return(false));
  ON_CALL(mock_app_mngr_, GetPluginManager())
      .WillByDefault(ReturnRef(mock_rpc_plugin_manager_));
  typedef am::plugin_manager::RPCPlugin RPCPlugin;
  utils::Optional<RPCPlugin> mock_rpc_plugin_opt = mock_rpc_plugin_;
  ON_CALL(mock_rpc_plugin_manager_, FindPluginToProcess(kFunctionId, source))
      .WillByDefault(Return(mock_rpc_plugin_opt));
  ON_CALL(mock_rpc_plugin_, GetCommandFactory())
      .WillByDefault(ReturnRef(mock_command_factory_));
  std::shared_ptr<MockRequest> cmd;
  ON_CALL(mock_command_factory_, CreateCommand(message, source))
      .WillByDefault(Return(cmd));
  ASSERT_FALSE(rpc_service_->ManageHMICommand(message, source));
}

TEST_F(RPCServiceImplTest, ManageHMICommand_IsAppInReconnectMode_True) {
  auto message = CreateMessage();
  auto source = am::commands::Command::CommandSource::SOURCE_HMI;
  (*message)[am::strings::params][am::strings::function_id] = kFunctionId;
  (*message)[am::strings::msg_params][am::strings::app_id] = kAppId;
  ON_CALL(mock_app_mngr_, IsLowVoltage()).WillByDefault(Return(false));
  ON_CALL(mock_app_mngr_, GetPluginManager())
      .WillByDefault(ReturnRef(mock_rpc_plugin_manager_));
  typedef am::plugin_manager::RPCPlugin RPCPlugin;
  utils::Optional<RPCPlugin> mock_rpc_plugin_opt = mock_rpc_plugin_;
  ON_CALL(mock_rpc_plugin_manager_, FindPluginToProcess(kFunctionId, source))
      .WillByDefault(Return(mock_rpc_plugin_opt));
  ON_CALL(mock_rpc_plugin_, GetCommandFactory())
      .WillByDefault(ReturnRef(mock_command_factory_));
  std::shared_ptr<MockRequest> cmd =
      std::make_shared<MockRequest>(kConnectionKey, kCorrelationId);
  ON_CALL(mock_command_factory_, CreateCommand(message, source))
      .WillByDefault(Return(cmd));

  auto mock_app = std::make_shared<NiceMock<MockApplication> >();
  ON_CALL(mock_app_mngr_, application(kConnectionKey))
      .WillByDefault(Return(mock_app));
  const connection_handler::DeviceHandle device_id1 = 1u;
  ON_CALL(*mock_app, device()).WillByDefault(Return(device_id1));
  ON_CALL(*mock_app, policy_app_id()).WillByDefault(Return(kPolicyAppId));

  ON_CALL(mock_app_mngr_, IsAppInReconnectMode(device_id1, kPolicyAppId))
      .WillByDefault(Return(true));
  EXPECT_CALL(mock_command_holder_,
              Suspend(static_cast<am::ApplicationSharedPtr>(mock_app),
                      am::CommandHolder::CommandType::kHmiCommand,
                      source,
                      message))
      .WillOnce(Return());
  ASSERT_TRUE(rpc_service_->ManageHMICommand(message, source));
}

TEST_F(RPCServiceImplTest,
       ManageHMICommand_MessageTypeUnknownTypeCommandNotInit_ReturnFalse) {
  auto message = CreateMessage();
  auto source = am::commands::Command::CommandSource::SOURCE_HMI;
  (*message)[am::strings::params][am::strings::function_id] = kFunctionId;
  (*message)[am::strings::params][am::strings::message_type] = am::kUnknownType;
  ON_CALL(mock_app_mngr_, IsLowVoltage()).WillByDefault(Return(false));
  ON_CALL(mock_app_mngr_, GetPluginManager())
      .WillByDefault(ReturnRef(mock_rpc_plugin_manager_));
  typedef am::plugin_manager::RPCPlugin RPCPlugin;
  utils::Optional<RPCPlugin> mock_rpc_plugin_opt = mock_rpc_plugin_;
  ON_CALL(mock_rpc_plugin_manager_, FindPluginToProcess(kFunctionId, source))
      .WillByDefault(Return(mock_rpc_plugin_opt));
  ON_CALL(mock_rpc_plugin_, GetCommandFactory())
      .WillByDefault(ReturnRef(mock_command_factory_));
  std::shared_ptr<MockRequest> cmd =
      std::make_shared<MockRequest>(kConnectionKey, kCorrelationId);
  ON_CALL(mock_command_factory_, CreateCommand(message, source))
      .WillByDefault(Return(cmd));

  EXPECT_CALL(*cmd, Init()).WillOnce(Return(false));
  ASSERT_FALSE(rpc_service_->ManageHMICommand(message, source));
}

TEST_F(RPCServiceImplTest, SendMessageToMobile) {
  MessageSharedPtr message;
  EXPECT_CALL(mock_app_mngr_, application(_)).Times(0);
  rpc_service_->SendMessageToMobile(message);
}

}  // namespace application_manager_test

}  // namespace components

}  // namespace test
