/**
 * @file
 * LightWeightM2M LWM2M Flow Access object.
 *
 * @author Imagination Technologies
 *
 * @copyright Copyright (c) 2016, Imagination Technologies Limited and/or its affiliated group
 * companies and/or licensors.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 *    and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 *    endorse or promote products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/***************************************************************************************************
 * Includes
 **************************************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "coap_abstraction.h"

#include <awa/static.h>

/***************************************************************************************************
 * Definitions
 **************************************************************************************************/

#define FLOWM2M_FLOW_ACCESS_OBJECT                                20001
#define FLOWM2M_FLOW_ACCESS_OBJECT_URL                            0
#define FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY                    1
#define FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET                 2
#define FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN                3
#define FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY          4

#define FLOW_ACCESS_INSTANCES 1


typedef struct
{
	char URL[64];
	char CustomerKey[64];
	char CustomerSecret[64];
	char RememberMeToken[64];
	AwaTime RememberMeTokenExpiry;
} FlowAccessObject;

FlowAccessObject flowAccess[FLOW_ACCESS_INSTANCES];

/***************************************************************************************************
 * Implementation - Public
 **************************************************************************************************/

int DefineFlowAccessObject(AwaStaticClient *awaClient)
{
	AwaStaticClient_DefineObject(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, "FlowAccess", 0, FLOW_ACCESS_INSTANCES);

	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_URL,                   "URL",                   AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_URL,                   flowAccess[0].URL, sizeof(flowAccess[0].URL), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY,           "CustomerKey",           AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY,           flowAccess[0].CustomerKey, sizeof(flowAccess[0].CustomerKey), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET,        "CustomerSecret",        AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET,        flowAccess[0].CustomerSecret, sizeof(flowAccess[0].CustomerSecret), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN,       "RememberMeToken",       AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN,       flowAccess[0].RememberMeToken, sizeof(flowAccess[0].RememberMeToken), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY, "RememberMeTokenExpiry", AwaResourceType_Time,   0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY, flowAccess[0].RememberMeTokenExpiry, sizeof(flowAccess[0].RememberMeTokenExpiry), 0);

	return 0;
}
