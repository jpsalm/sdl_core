/*
 * Copyright (c) 2017, Ford Motor Company
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

#include "transport_manager/transport_manager_default.h"
#include "gtest/gtest.h"
#include "resumption/mock_last_state.h"
#include "transport_manager/mock_transport_manager_settings.h"
#include "transport_manager/transport_manager.h"

namespace test {
namespace components {
namespace transport_manager_test {

using resumption_test::MockLastState;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

namespace {
const std::string kDeviceName = "name";
const std::string kDeviceAddress = "address";
const std::string kDeviceApplications = "applications";
const std::string kApplicationPort = "port";
const std::string kApplicationPortValue = "12345";
const std::string kApplicationRfcomm = "rfcomm_channel";
const std::string kApplicationRfcommValue = "7";
const std::string kTransportManager = "TransportManager";
const std::string kTcpAdapter = "TcpAdapter";
const std::string kBluetoothAdapter = "BluetoothAdapter";
const std::string kDevices = "devices";
std::vector<uint8_t> kBTUUID = {0x93,
                                0x6D,
                                0xA0,
                                0x1F,
                                0x9A,
                                0xBD,
                                0x4D,
                                0x9D,
                                0x80,
                                0xC7,
                                0x02,
                                0xAF,
                                0x85,
                                0xC8,
                                0x22,
                                0xA8};
}  // namespace

// cppcheck-suppress syntaxError
TEST(TestTransportManagerDefault, Init_LastStateNotUsed) {
  MockTransportManagerSettings transport_manager_settings;
  transport_manager::TransportManagerDefault transport_manager(
      transport_manager_settings);

  NiceMock<MockLastState> mock_last_state;
  Json::Value custom_dictionary = Json::Value();

  ON_CALL(mock_last_state, get_dictionary())
      .WillByDefault(ReturnRef(custom_dictionary));

  EXPECT_CALL(transport_manager_settings, use_last_state())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(transport_manager_settings, transport_manager_tcp_adapter_port())
      .WillRepeatedly(Return(12345u));
  std::string network_interface = "";
  EXPECT_CALL(transport_manager_settings,
              transport_manager_tcp_adapter_network_interface())
      .WillRepeatedly(ReturnRef(network_interface));
  EXPECT_CALL(transport_manager_settings, bluetooth_uuid())
      .WillRepeatedly(Return(kBTUUID.data()));

  std::string dummy_parameter;
  EXPECT_CALL(transport_manager_settings, aoa_filter_manufacturer())
      .WillRepeatedly(ReturnRef(dummy_parameter));
  EXPECT_CALL(transport_manager_settings, aoa_filter_model_name())
      .WillRepeatedly(ReturnRef(dummy_parameter));
  EXPECT_CALL(transport_manager_settings, aoa_filter_description())
      .WillRepeatedly(ReturnRef(dummy_parameter));
  EXPECT_CALL(transport_manager_settings, aoa_filter_version())
      .WillRepeatedly(ReturnRef(dummy_parameter));
  EXPECT_CALL(transport_manager_settings, aoa_filter_uri())
      .WillRepeatedly(ReturnRef(dummy_parameter));
  EXPECT_CALL(transport_manager_settings, aoa_filter_serial_number())
      .WillRepeatedly(ReturnRef(dummy_parameter));
  transport_manager.Init(mock_last_state);
  transport_manager.Stop();
}

TEST(TestTransportManagerDefault, Init_LastStateUsed) {
  MockTransportManagerSettings transport_manager_settings;
  transport_manager::TransportManagerDefault transport_manager(
      transport_manager_settings);

  NiceMock<MockLastState> mock_last_state;
  Json::Value custom_dictionary;
  Json::Value tcp_device;
  tcp_device[kDeviceName] = "unique_tcp_device_name";
  tcp_device[kDeviceAddress] = "127.0.0.1";
  tcp_device[kDeviceApplications][0][kApplicationPort] = kApplicationPortValue;
  Json::Value bluetooth_device;
  bluetooth_device[kDeviceName] = "unique_bluetooth_device_name";
  bluetooth_device[kDeviceAddress] = "AB:CD:EF:GH:IJ:KL";
  bluetooth_device[kDeviceApplications][0][kApplicationRfcomm] =
      kApplicationRfcommValue;
  custom_dictionary[kTransportManager][kTcpAdapter][kDevices][0] = tcp_device;
  custom_dictionary[kTransportManager][kBluetoothAdapter][kDevices][0] =
      bluetooth_device;

  ON_CALL(mock_last_state, get_dictionary())
      .WillByDefault(ReturnRef(custom_dictionary));

  EXPECT_CALL(transport_manager_settings, use_last_state())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(transport_manager_settings, transport_manager_tcp_adapter_port())
      .WillRepeatedly(Return(12345u));
  std::string network_interface = "";
  EXPECT_CALL(transport_manager_settings,
              transport_manager_tcp_adapter_network_interface())
      .WillRepeatedly(ReturnRef(network_interface));
  EXPECT_CALL(transport_manager_settings, bluetooth_uuid())
      .WillRepeatedly(Return(kBTUUID.data()));
  transport_manager.Init(mock_last_state);
  transport_manager.Stop();
}

TEST(TestTransportManagerDefault, Init_LastStateUsed_InvalidPort) {
  MockTransportManagerSettings transport_manager_settings;
  transport_manager::TransportManagerDefault transport_manager(
      transport_manager_settings);

  NiceMock<MockLastState> mock_last_state;
  Json::Value custom_dictionary;
  Json::Value tcp_device;
  tcp_device[kDeviceName] = "unique_tcp_device_name";
  tcp_device[kDeviceAddress] = "127.0.0.1";
  tcp_device[kDeviceApplications][0][kApplicationPort] = "1";
  Json::Value bluetooth_device;
  bluetooth_device[kDeviceName] = "unique_bluetooth_device_name";
  bluetooth_device[kDeviceAddress] = "AB:CD:EF:GH:IJ:KL";
  bluetooth_device[kDeviceApplications][0][kApplicationRfcomm] =
      kApplicationRfcommValue;
  custom_dictionary[kTransportManager][kTcpAdapter][kDevices][0] = tcp_device;
  custom_dictionary[kTransportManager][kBluetoothAdapter][kDevices][0] =
      bluetooth_device;

  ON_CALL(mock_last_state, get_dictionary())
      .WillByDefault(ReturnRef(custom_dictionary));

  EXPECT_CALL(transport_manager_settings, use_last_state())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(transport_manager_settings, transport_manager_tcp_adapter_port())
      .WillRepeatedly(Return(1u));
  std::string network_interface = "";
  EXPECT_CALL(transport_manager_settings,
              transport_manager_tcp_adapter_network_interface())
      .WillRepeatedly(ReturnRef(network_interface));
  EXPECT_CALL(transport_manager_settings, bluetooth_uuid())
      .WillRepeatedly(Return(kBTUUID.data()));
  transport_manager.Init(mock_last_state);
  transport_manager.Stop();
}

}  // namespace transport_manager_test
}  // namespace components
}  // namespace test
