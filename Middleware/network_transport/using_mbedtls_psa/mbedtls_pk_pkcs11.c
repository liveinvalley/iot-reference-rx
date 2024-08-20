/*
 * FreeRTOS V202112.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

#include "logging_levels.h"

#define LIBRARY_LOG_NAME     "MbedTLSPkP11"
#define LIBRARY_LOG_LEVEL    LOG_ERROR

#include "logging_stack.h"

/**
 * @file mbedtls_pk_pkcs11.c
 * @brief mbedtls_pk implementation for pkcs11 ECDSA and RSA keys.
 *           Exports a mbedtls_pk_info_t type.
 */

#include <string.h>

/* Mbedtls Includes */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"
#include "pk_wrap.h"

#include "core_pkcs11_config.h"
#include "core_pkcs11.h"

/*-----------------------------------------------------------*/

int lPKCS11RandomCallback( void * pvCtx,
                           unsigned char * pucOutput,
                           size_t uxLen )
{
    int lRslt;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_SESSION_HANDLE * pxSessionHandle = ( CK_SESSION_HANDLE * ) pvCtx;

    if( pucOutput == NULL )
    {
        lRslt = -1;
    }
    else if( pvCtx == NULL )
    {
        lRslt = -1;
        LogError( ( "pvCtx must not be NULL." ) );
    }
    else
    {
        lRslt = ( int ) C_GetFunctionList( &pxFunctionList );
    }

    if( ( lRslt != CKR_OK ) ||
        ( pxFunctionList == NULL ) ||
        ( pxFunctionList->C_GenerateRandom == NULL ) )
    {
        lRslt = -1;
    }
    else
    {
        lRslt = ( int ) pxFunctionList->C_GenerateRandom( *pxSessionHandle, pucOutput, uxLen );
    }

    return lRslt;
}

/*-----------------------------------------------------------*/
