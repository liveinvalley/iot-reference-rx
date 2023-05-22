/*
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 * Modifications Copyright (C) 2023 Renesas Electronics Corporation. or its affiliates.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*******************************************************************************
* Copyright (C) 2023 Renesas Electronics Corporation. All rights reserved.
*
* DISCLAIMER
* This software is supplied by Renesas Electronics Corporation and is only
* intended for use with Renesas products. No other uses are authorized. This
* software is owned by Renesas Electronics Corporation and is protected under
* all applicable laws, including copyright laws.
* THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
* THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT
* LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
* AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED.
* TO THE MAXIMUM EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS
* ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES SHALL BE LIABLE
* FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR
* ANY REASON RELATED TO THIS SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE
* BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
* Renesas reserves the right, without notice, to make changes to this software
* and to discontinue the availability of this software. By using this software,
* you agree to the additional terms and conditions found by accessing the
* following link:
* http://www.renesas.com/disclaimer
*******************************************************************************/

/**
 * @file ota_demo_config.h
 * @brief Configuration options for the OTA related demos.
 */

#ifndef OTA_DEMO_CONFIG_H_
#define OTA_DEMO_CONFIG_H_

/**
 * @brief Certificate used for validating code signing signatures in the OTA PAL.
 */
#ifndef otapalconfigCODE_SIGNING_CERTIFICATE
    #define otapalconfigCODE_SIGNING_CERTIFICATE    "Insert code signing certificate..."
#endif

/**
 * @brief Major version of the firmware.
 *
 * This is used in the OTA demo to set the appFirmwareVersion variable that is
 * declared in the ota_appversion32.h file in the OTA library.
 */
#ifndef APP_VERSION_MAJOR
    #define APP_VERSION_MAJOR    0
#endif

/**
 * @brief Minor version of the firmware.
 *
 * This is used in the OTA demo to set the appFirmwareVersion variable that is
 * declared in the ota_appversion32.h file in the OTA library.
 */
#ifndef APP_VERSION_MINOR
    #define APP_VERSION_MINOR    9
#endif

/**
 * @brief Build version of the firmware.
 *
 * This is used in the OTA demo to set the appFirmwareVersion variable that is
 * declared in the ota_appversion32.h file in the OTA library.
 */
#ifndef APP_VERSION_BUILD
    #define APP_VERSION_BUILD    2
#endif

/**
 * @brief Server's root CA certificate.
 *
 * This certificate is used to identify the AWS IoT server and is publicly
 * available. Refer to the AWS documentation available in the link below for
 * information about the Server Root CAs.
 * https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
 *
 * @note The TI C3220 Launchpad board requires that the Root CA have its
 * certificate self-signed. As mentioned in the above link, the Amazon Root CAs
 * are cross-signed by the Starfield Root CA. Thus, ONLY the Starfield Root CA
 * can be used to connect to the ATS endpoints on AWS IoT for the TI board.
 *
 * @note This certificate should be PEM-encoded.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 *
 */
#define democonfigROOT_CA_PEM                   tlsSTARFIELD_ROOT_CERTIFICATE_PEM

/**
 * @brief Timeout for which MQTT library keeps polling the transport interface,
 * when no byte is received.
 *
 * The timeout is honoured only after the first byte is read and while
 * remaining bytes are read from network interface. Keeping this timeout to a
 * sufficiently large value so as to account for delay of receipt of a large
 * block of message.
 */
#define MQTT_RECV_POLLING_TIMEOUT_MS            ( 1000U )

/**
 * @brief The length of the queue used to hold commands for the agent.
 */
#define MQTT_AGENT_COMMAND_QUEUE_LENGTH         ( 25 )

/**
 * @brief Dimensions the buffer used to serialise and deserialise MQTT packets.
 * @note Specified in bytes.  Must be large enough to hold the maximum
 * anticipated MQTT payload.
 */
#define MQTT_AGENT_NETWORK_BUFFER_SIZE          ( 5000 )

/**
 * @brief Maximum time MQTT agent waits in the queue for any pending MQTT
 * operations.
 *
 * The wait time is kept smallest possible to increase the responsiveness of
 * MQTT agent while processing  pending MQTT operations as well as receive
 * packets from network.
 */
#define MQTT_AGENT_MAX_EVENT_QUEUE_WAIT_TIME    ( 1U )

#endif /* OTA_DEMO_CONFIG_H_ */
