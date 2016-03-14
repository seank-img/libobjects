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
#include "lwm2m_core.h"
#include "coap_abstraction.h"
#include "common.h"

/***************************************************************************************************
 * Definitions
 **************************************************************************************************/

#define FLOWM2M_FLOW_ACCESS_OBJECT								20001
#define FLOWM2M_FLOW_ACCESS_OBJECT_URL							0
#define FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY					1
#define FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET				2
#define FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN				3
#define FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY		4

#define REGISTER_FLOW_ACCESS_OBJECT_RESOURCE(context, name, id, type) \
	REGISTER_RESOURCE(context, name, FLOWM2M_FLOW_ACCESS_OBJECT, id, type, \
		MultipleInstancesEnum_Single, MandatoryEnum_Mandatory, Operations_RW, \
		&flowAccessObjectResourceOperationHandlers)

#define CREATE_FLOW_ACCESS_OBJECT_OPTIONAL_RESOURCE(context, objectInstanceId, resourcId) \
	CREATE_OPTIONAL_RESOURCE(context, FLOWM2M_FLOW_OBJECT, objectInstanceId, resourcId)

/***************************************************************************************************
 * Typedefs
 **************************************************************************************************/

typedef struct
{
	char * URL;
	char * CustomerKey;
	char * CustomerSecret;
	char * RememberMeToken;
	int64_t RememberMeTokenExpiry;
} FlowAccessObject;

/***************************************************************************************************
 * Prototypes
 **************************************************************************************************/

static int FlowAccessObject_ResourceReadHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * destBuffer, int destBufferLen);

static int FlowAccessObject_ResourceGetLengthHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID);

static int FlowAccessObject_ResourceWriteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * srcBuffer, int srcBufferLen,
	bool * changed);

static int FlowAccessObject_ResourceCreateHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID);

static int FlowAccessObject_ObjectCreateInstanceHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID);

static int FlowAccessObject_ObjectDeleteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID);

/***************************************************************************************************
 * Globals
 **************************************************************************************************/

FlowAccessObject flowAccessObject;

static ObjectOperationHandlers flowAccessObjectOperationHandlers =
{
	.CreateInstance = FlowAccessObject_ObjectCreateInstanceHandler,
	.Delete = FlowAccessObject_ObjectDeleteHandler,
};

static ResourceOperationHandlers flowAccessObjectResourceOperationHandlers =
{
	.Read = FlowAccessObject_ResourceReadHandler,
	.GetLength = FlowAccessObject_ResourceGetLengthHandler,
	.Write = FlowAccessObject_ResourceWriteHandler,
	.CreateOptionalResource = FlowAccessObject_ResourceCreateHandler,
	.Execute = NULL,
};

/***************************************************************************************************
 * Implementation - Private
 **************************************************************************************************/

static int FlowAccessObject_ObjectCreateInstanceHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID)
{
	return 0;
}

static int FlowAccessObject_ResourceCreateHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID)
{
	return 0;
}

static int FlowAccessObject_ObjectDeleteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID)
{

	if (objectID != FLOWM2M_FLOW_ACCESS_OBJECT)
	{
		Lwm2m_Error("flowAccessObject_ObjectDeleteHandler Invalid OIR: %d/%d/%d\n", objectID,
			objectInstanceID, resourceID);
		return -1;
	}

	if (objectInstanceID == 0)
	{
		memset(&flowAccessObject, 0, sizeof(FlowAccessObject));

		if (flowAccessObject.URL)
			free(flowAccessObject.URL);
		if (flowAccessObject.CustomerKey)
			free(flowAccessObject.CustomerKey);
		if (flowAccessObject.CustomerSecret)
			free(flowAccessObject.CustomerSecret);
		if (flowAccessObject.RememberMeToken)
			free(flowAccessObject.RememberMeToken);
	}
	else
	{
		Lwm2m_Error("flowAccessObject_ObjectDeleteHandler Invalid instance (not 0): %d",
			objectInstanceID);
		return -1;
	}

	return 0;
}

static int FlowAccessObject_ResourceReadHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * destBuffer, int destBufferLen)
{
	int result = 0;

	switch (resourceID)
	{
		case FLOWM2M_FLOW_ACCESS_OBJECT_URL:
			memcpy(destBuffer, flowAccessObject.URL, strlen(flowAccessObject.URL) + 1);
			result = strlen(flowAccessObject.URL) + 1;
			break;
		case FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY:
			memcpy(destBuffer, flowAccessObject.CustomerKey,
				strlen(flowAccessObject.CustomerKey) + 1);
			result = strlen(flowAccessObject.CustomerKey) + 1;
			break;
		case FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET:
			memcpy(destBuffer, flowAccessObject.CustomerSecret,
				strlen(flowAccessObject.CustomerSecret) + 1);
			result = strlen(flowAccessObject.CustomerSecret) + 1;
			break;
		case FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN:
			memcpy(destBuffer, flowAccessObject.RememberMeToken,
				strlen(flowAccessObject.RememberMeToken) + 1);
			result = strlen(flowAccessObject.RememberMeToken) + 1;
			break;
		case FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY:
			memcpy(destBuffer, &flowAccessObject.RememberMeTokenExpiry,
				sizeof(flowAccessObject.RememberMeTokenExpiry));
			result = sizeof(flowAccessObject.RememberMeTokenExpiry);
			break;
		default:
			result = -1;
			break;
	}

	return result;
}

static int FlowAccessObject_ResourceGetLengthHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID)
{
	int result = 0;

	switch (resourceID)
	{
		case FLOWM2M_FLOW_ACCESS_OBJECT_URL:
			if(flowAccessObject.URL != NULL)
				result = strlen(flowAccessObject.URL) + 1;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY:
			if(flowAccessObject.CustomerKey != NULL)
				result = strlen(flowAccessObject.CustomerKey) + 1;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET:
			if(flowAccessObject.CustomerSecret != NULL)
				result = strlen(flowAccessObject.CustomerSecret) + 1;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN:
			if(flowAccessObject.RememberMeToken != NULL)
				result = strlen(flowAccessObject.RememberMeToken) + 1;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY:
			result = sizeof(flowAccessObject.RememberMeTokenExpiry);
			break;

		default:
			result = -1;
			break;
	}

	return result;
}

static int FlowAccessObject_ResourceWriteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * srcBuffer, int srcBufferLen,
	bool * changed)
{
	int result = 0;

	switch(resourceID)
	{
		case FLOWM2M_FLOW_ACCESS_OBJECT_URL:
			if (flowAccessObject.URL)
				free(flowAccessObject.URL);
			flowAccessObject.URL = (char *)malloc(srcBufferLen + 1);
			memset(flowAccessObject.URL, 0, srcBufferLen + 1);
			memcpy(flowAccessObject.URL, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY:
			if (flowAccessObject.CustomerKey)
				free(flowAccessObject.CustomerKey);
			flowAccessObject.CustomerKey = (char *)malloc(srcBufferLen + 1);
			memset(flowAccessObject.CustomerKey, 0, srcBufferLen + 1);
			memcpy(flowAccessObject.CustomerKey, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET:
			if (flowAccessObject.CustomerSecret)
				free(flowAccessObject.CustomerSecret);
			flowAccessObject.CustomerSecret = (char *)malloc(srcBufferLen + 1);
			memset(flowAccessObject.CustomerSecret, 0, srcBufferLen + 1);
			memcpy(flowAccessObject.CustomerSecret, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN:
			if (flowAccessObject.RememberMeToken)
				free(flowAccessObject.RememberMeToken);
			flowAccessObject.RememberMeToken = (char *)malloc(srcBufferLen + 1);
			memset(flowAccessObject.RememberMeToken, 0, srcBufferLen + 1);
			memcpy(flowAccessObject.RememberMeToken, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY:
			memcpy(&flowAccessObject.RememberMeTokenExpiry, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		default:
			result = -1;
			break;
	}

	return result;
}

/***************************************************************************************************
 * Implementation - Public
 **************************************************************************************************/

int Lwm2m_RegisterFlowAccessObject(Lwm2mContextType * context)
{
	Lwm2mCore_RegisterObjectType(context, "FlowAccess" , FLOWM2M_FLOW_ACCESS_OBJECT,
		MultipleInstancesEnum_Single, MandatoryEnum_Optional, &flowAccessObjectOperationHandlers);

	REGISTER_FLOW_ACCESS_OBJECT_RESOURCE(context, "URL", FLOWM2M_FLOW_ACCESS_OBJECT_URL, \
		ResourceTypeEnum_TypeString);
	REGISTER_FLOW_ACCESS_OBJECT_RESOURCE(context, "CustomerKey", \
		FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY, ResourceTypeEnum_TypeString);
	REGISTER_FLOW_ACCESS_OBJECT_RESOURCE(context, "CustomerSecret", \
		FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET, ResourceTypeEnum_TypeString);
	REGISTER_FLOW_ACCESS_OBJECT_RESOURCE(context, "RememberMeToken", \
		FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN, ResourceTypeEnum_TypeString);
	REGISTER_FLOW_ACCESS_OBJECT_RESOURCE(context, "RememberMeTokenExpiry", \
		FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY, ResourceTypeEnum_TypeOpaque);

	return 0;
}
