/**
 * @file
 * LightWeightM2M LWM2M Flow object.
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
#include <inttypes.h>
#include "lwm2m_core.h"
#include "coap_abstraction.h"
#include "hmac.h"
#include "b64.h"
#include "common.h"

/***************************************************************************************************
 * Definitions
 **************************************************************************************************/

#define FLOWM2M_FLOW_OBJECT							20000
#define FLOWM2M_FLOW_OBJECT_DEVICEID				0
#define FLOWM2M_FLOW_OBJECT_PARENTID				1
#define FLOWM2M_FLOW_OBJECT_DEVICETYPE				2
#define FLOWM2M_FLOW_OBJECT_NAME					3
#define FLOWM2M_FLOW_OBJECT_DESCRIPTION				4
#define FLOWM2M_FLOW_OBJECT_FCAP					5
#define FLOWM2M_FLOW_OBJECT_LICENSEEID				6
#define FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE		7
#define FLOWM2M_FLOW_OBJECT_HASHITERATIONS			8
#define FLOWM2M_FLOW_OBJECT_LICENSEEHASH			9
#define FLOWM2M_FLOW_OBJECT_STATUS					10

#define MAX_STRING_SIZE								64
#define MAX_KEY_SIZE								64

#define REGISTER_FLOW_OBJECT_RESOURCE(context, name, id, type, minInstances) \
	REGISTER_RESOURCE(context, name, FLOWM2M_FLOW_OBJECT, id, type, \
		MultipleInstancesEnum_Single, minInstances, Operations_RW, \
		&flowObjectResourceOperationHandlers)

#define CREATE_FLOW_OBJECT_OPTIONAL_RESOURCE(context, objectInstanceId, resourcId) \
	CREATE_OPTIONAL_RESOURCE(context, FLOWM2M_FLOW_OBJECT, objectInstanceId, resourcId)

/***************************************************************************************************
 * Typedefs
 **************************************************************************************************/

typedef struct
{
	void * DeviceID;
	int DeviceIDSize;
	void * ParentID;
	int64_t ParentIDSize;
	char * DeviceType;
	char * Name;
	char * Description;
	char * FCAP;
	int64_t LicenseeID;
	void * LicenseeChallenge;
	int64_t LicenseeChallengeSize;
	int64_t HashIterations;
	void * LicenseeHash;
	int64_t LicenseeHashSize;
	int64_t Status;
} FlowObject;

/***************************************************************************************************
 * Prototypes
 **************************************************************************************************/

static int FlowObject_ResourceReadHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * destBuffer, int destBufferLen);

static int FlowObject_ResourceGetLengthHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID);

static int FlowObject_ResourceWriteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * srcBuffer, int srcBufferLen,
	bool * changed);

static int FlowObject_ResourceCreateHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID);

static int FlowObject_ObjectCreateInstanceHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID);

static int FlowObject_ObjectDeleteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID);

/***************************************************************************************************
 * Globals
 **************************************************************************************************/

static char licenseeSecret[MAX_STRING_SIZE] = "getATTtDsNBpBRnMsN7GoQ==";
FlowObject flowObject;

static ObjectOperationHandlers flowObjectOperationHandlers =
{
	.CreateInstance = FlowObject_ObjectCreateInstanceHandler,
	.Delete = FlowObject_ObjectDeleteHandler,
};

static ResourceOperationHandlers flowObjectResourceOperationHandlers =
{
	.Read = FlowObject_ResourceReadHandler,
	.GetLength = FlowObject_ResourceGetLengthHandler,
	.Write = FlowObject_ResourceWriteHandler,
	.CreateOptionalResource = FlowObject_ResourceCreateHandler,
	.Execute = NULL,
};

/***************************************************************************************************
 * Implementation - Private
 **************************************************************************************************/

static int FlowObject_ObjectCreateInstanceHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID)
{
	return 0;
}

static int FlowObject_ResourceCreateHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID)
{
	return 0;
}

static int FlowObject_ObjectDeleteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID)
{

	if (objectID != FLOWM2M_FLOW_OBJECT)
	{
		Lwm2m_Error("FlowObject_ObjectDeleteHandler Invalid OIR: %d/%d/%d\n", objectID,
			objectInstanceID, resourceID);
		return -1;
	}

	if (objectInstanceID == 0)
	{
		memset(&flowObject, 0, sizeof(FlowObject));

		if(flowObject.DeviceID)
			free(flowObject.DeviceID);
		if(flowObject.ParentID)
			free(flowObject.ParentID);
		if(flowObject.DeviceType)
			free(flowObject.DeviceType);
		if(flowObject.Name)
			free(flowObject.Name);
		if(flowObject.Description)
			free(flowObject.Description);
		if(flowObject.FCAP)
			free(flowObject.FCAP);
		if(flowObject.LicenseeChallenge)
			free(flowObject.LicenseeChallenge);
		if(flowObject.LicenseeHash)
			free(flowObject.LicenseeHash);
	}
	else
	{
		Lwm2m_Error("FlowObject_ObjectDeleteHandler Invalid instance (not 0): %d", objectInstanceID);
		return -1;
	}

	return 0;
}

static int FlowObject_ResourceReadHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * destBuffer, int destBufferLen)
{
	int result = 0;

	switch (resourceID)
	{
		case FLOWM2M_FLOW_OBJECT_DEVICEID:
			if(flowObject.DeviceID != NULL)
			{
				memcpy(destBuffer, flowObject.DeviceID, flowObject.DeviceIDSize);
				result = flowObject.DeviceIDSize;
			}
			break;

		case FLOWM2M_FLOW_OBJECT_PARENTID:
			if(flowObject.ParentID != NULL)
			{
				memcpy(destBuffer, flowObject.ParentID, flowObject.ParentIDSize);
				result = flowObject.ParentIDSize;
			}
			break;

		case FLOWM2M_FLOW_OBJECT_DEVICETYPE:
			if(flowObject.DeviceType != NULL)
			{
				memcpy(destBuffer, flowObject.DeviceType, strlen(flowObject.DeviceType) + 1);
				result = strlen(flowObject.DeviceType);
			}
			break;

		case FLOWM2M_FLOW_OBJECT_NAME:
			if(flowObject.Name != NULL)
			{
				memcpy(destBuffer, flowObject.Name, strlen(flowObject.Name) + 1);
				result = strlen(flowObject.Name) + 1;
			}
			break;

		case FLOWM2M_FLOW_OBJECT_DESCRIPTION:
			if(flowObject.Description != NULL)
			{
				memcpy(destBuffer, flowObject.Description, strlen(flowObject.Description) + 1);
				result = strlen(flowObject.Description) + 1;
			}
			break;

		case FLOWM2M_FLOW_OBJECT_FCAP:
			if(flowObject.FCAP != NULL)
			{
				memcpy(destBuffer, flowObject.FCAP, strlen(flowObject.FCAP) + 1);
				result = strlen(flowObject.FCAP) + 1;
			}
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEEID:
			memcpy(destBuffer, &flowObject.LicenseeID, sizeof(flowObject.LicenseeID));
			result = sizeof(flowObject.LicenseeID);
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE:
			if(flowObject.LicenseeChallenge != NULL)
			{
				memcpy(destBuffer, flowObject.LicenseeChallenge, flowObject.LicenseeChallengeSize);
				result = flowObject.LicenseeChallengeSize;
			}
			break;

		case FLOWM2M_FLOW_OBJECT_HASHITERATIONS:
			memcpy(destBuffer, &flowObject.HashIterations, sizeof(flowObject.HashIterations));
			result = sizeof(flowObject.HashIterations);
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEEHASH:
			if(flowObject.LicenseeHash != NULL)
			{
				memcpy(destBuffer, flowObject.LicenseeHash, flowObject.LicenseeHashSize);
				result = flowObject.LicenseeHashSize;
			}
			break;

		case FLOWM2M_FLOW_OBJECT_STATUS:
			memcpy(destBuffer, &flowObject.Status, sizeof(flowObject.Status));
			result = sizeof(flowObject.Status);
			break;

		default:
			result = -1;
			break;
	}

	return result;
}

static int FlowObject_ResourceGetLengthHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID)
{
	int result = 0;

	switch (resourceID)
	{
		case FLOWM2M_FLOW_OBJECT_DEVICEID:
			result = flowObject.DeviceIDSize;
			break;

		case FLOWM2M_FLOW_OBJECT_PARENTID:
			result = flowObject.ParentIDSize;
			break;

		case FLOWM2M_FLOW_OBJECT_DEVICETYPE:
			if(flowObject.DeviceType != NULL)
				result = strlen(flowObject.DeviceType) + 1;
			break;

		case FLOWM2M_FLOW_OBJECT_NAME:
			if(flowObject.Name != NULL)
				result = strlen(flowObject.Name) + 1;
			break;

		case FLOWM2M_FLOW_OBJECT_DESCRIPTION:
			if(flowObject.Description != NULL)
				result = strlen(flowObject.Description) + 1;
			break;

		case FLOWM2M_FLOW_OBJECT_FCAP:
			if(flowObject.FCAP != NULL)
				result = strlen(flowObject.FCAP) + 1;
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEEID:
			result = sizeof(flowObject.LicenseeID);
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE:
			result = flowObject.LicenseeChallengeSize;
			break;

		case FLOWM2M_FLOW_OBJECT_HASHITERATIONS:
			result = sizeof(flowObject.HashIterations);
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEEHASH:
			result = flowObject.LicenseeHashSize;
			break;

		case FLOWM2M_FLOW_OBJECT_STATUS:
			result = sizeof(flowObject.Status);
			break;

		default:
			result = -1;
			break;
	}

	return result;
}

static bool CalculateLicenseeHash(char * licenseeSecret, uint8_t hash[SHA256_HASH_LENGTH],
	const char * challenge, int challengeLength, int iterations)
{
	int i;
	uint8_t key[MAX_KEY_SIZE];
	int keyLen = b64Decode(key, sizeof(key), licenseeSecret, strlen(licenseeSecret));

	if (keyLen == -1)
	{
		return false;
	}

	HmacSha256_ComputeHash(hash, challenge, challengeLength, key, keyLen);
	for (i = 1; i < iterations; i++)
	{
		HmacSha256_ComputeHash(hash, hash, SHA256_HASH_LENGTH, key, keyLen);
	}
	return true;
}

static int FlowObject_ResourceWriteHandler(void * context, ObjectIDType objectID,
	ObjectInstanceIDType objectInstanceID, ResourceIDType resourceID,
	ResourceInstanceIDType resourceInstanceID, uint8_t * srcBuffer, int srcBufferLen, bool * changed)
{
	int result;

	switch(resourceID)
	{
		case FLOWM2M_FLOW_OBJECT_DEVICEID:
			if(flowObject.DeviceID)
				free(flowObject.DeviceID);
			flowObject.DeviceID = malloc(srcBufferLen);
			memcpy(flowObject.DeviceID, srcBuffer, srcBufferLen);
			result = flowObject.DeviceIDSize = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_PARENTID:
			if(flowObject.ParentID)
				free(flowObject.ParentID);
			flowObject.ParentID = malloc(srcBufferLen);
			memcpy(flowObject.ParentID, srcBuffer, srcBufferLen);
			result = flowObject.ParentIDSize = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_DEVICETYPE:
			if(flowObject.DeviceType)
				free(flowObject.DeviceType);
			flowObject.DeviceType = malloc(srcBufferLen + 1);
			memset(flowObject.DeviceType, 0, srcBufferLen + 1);
			memcpy(flowObject.DeviceType, srcBuffer, srcBufferLen);
			Lwm2m_Debug("Device type: %s\n", flowObject.DeviceType);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_NAME:
			if(flowObject.Name)
				free(flowObject.Name);
			flowObject.Name = malloc(srcBufferLen + 1);
			memset(flowObject.Name, 0, srcBufferLen + 1);
			memcpy(flowObject.Name, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_DESCRIPTION:
			if(flowObject.Description)
				free(flowObject.Description);
			flowObject.Description = malloc(srcBufferLen + 1);
			memset(flowObject.Description, 0, srcBufferLen + 1);
			memcpy(flowObject.Description, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_FCAP:
			if(flowObject.FCAP)
				free(flowObject.FCAP);
			flowObject.FCAP = malloc(srcBufferLen + 1);
			memset(flowObject.FCAP, 0, srcBufferLen + 1);
			memcpy(flowObject.FCAP, srcBuffer, srcBufferLen);
			Lwm2m_Error("FCAP: %s\n", flowObject.FCAP);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEEID:
			memcpy(&flowObject.LicenseeID, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE:
			if(flowObject.LicenseeChallenge)
				free(flowObject.LicenseeChallenge);
			flowObject.LicenseeChallenge = malloc(srcBufferLen);
			memcpy(flowObject.LicenseeChallenge, srcBuffer, srcBufferLen);
			result = flowObject.LicenseeChallengeSize = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_HASHITERATIONS:
			memcpy(&flowObject.HashIterations, srcBuffer, srcBufferLen);
			result = srcBufferLen;
			break;

		case FLOWM2M_FLOW_OBJECT_LICENSEEHASH:
			if(flowObject.LicenseeHash)
				free(flowObject.LicenseeHash);
			flowObject.LicenseeHash = malloc(srcBufferLen);
			memcpy(flowObject.LicenseeHash, srcBuffer, srcBufferLen);
			result = flowObject.LicenseeHashSize = srcBufferLen;
			*changed = true;
			break;

		case FLOWM2M_FLOW_OBJECT_STATUS:
			memcpy(&flowObject.Status, srcBuffer, srcBufferLen);
			Lwm2m_Debug("Status: %d\n", (int)flowObject.Status);
			result = srcBufferLen;
			break;

		default:
			result = -1;
			break;
	}

	if(flowObject.HashIterations > 0 &&
		flowObject.LicenseeChallengeSize > 0 &&
		flowObject.LicenseeChallenge != NULL &&
		(resourceID == FLOWM2M_FLOW_OBJECT_HASHITERATIONS ||
		(resourceID == FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE)))
	{
		uint8_t licenseeHash[SHA256_HASH_LENGTH];

		Lwm2m_Debug("Calculating licensee hash with %d iterations...\n",
			(int)flowObject.HashIterations);

		if (CalculateLicenseeHash(licenseeSecret, licenseeHash, flowObject.LicenseeChallenge,
			flowObject.LicenseeChallengeSize, flowObject.HashIterations))
		{
			Lwm2m_Debug("Calculated hash, writing Licensee Hash resource...\n");
			if (Lwm2mCore_SetResourceInstanceValue(context, FLOWM2M_FLOW_OBJECT, 0,
				FLOWM2M_FLOW_OBJECT_LICENSEEHASH, 0, licenseeHash, sizeof(licenseeHash)) == -1)
			{
				Lwm2m_Error("Failed to set Licensee Hash\n");
				return -1;
			}
		}
		else
		{
			Lwm2m_Error("Licensee secret is invalid\n");
			return -1;
		}
	}

	return result;
}

/***************************************************************************************************
 * Implementation - Public
 **************************************************************************************************/

int Lwm2m_RegisterFlowObject(Lwm2mContextType * context)
{
	REGISTER_OBJECT(context, "FlowObject", FLOWM2M_FLOW_OBJECT, MultipleInstancesEnum_Single, \
		MandatoryEnum_Optional, &flowObjectOperationHandlers);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "DeviceID", FLOWM2M_FLOW_OBJECT_DEVICEID, \
		ResourceTypeEnum_TypeOpaque, MandatoryEnum_Mandatory);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "ParentID", FLOWM2M_FLOW_OBJECT_PARENTID, \
		ResourceTypeEnum_TypeOpaque, MandatoryEnum_Optional);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "DeviceType", FLOWM2M_FLOW_OBJECT_DEVICETYPE, \
		ResourceTypeEnum_TypeString, MandatoryEnum_Mandatory);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "Name", FLOWM2M_FLOW_OBJECT_NAME, \
		ResourceTypeEnum_TypeString, MandatoryEnum_Optional);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "Description", FLOWM2M_FLOW_OBJECT_DESCRIPTION, \
		ResourceTypeEnum_TypeString, MandatoryEnum_Optional);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "FCAP", FLOWM2M_FLOW_OBJECT_FCAP, \
		ResourceTypeEnum_TypeString, MandatoryEnum_Mandatory);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "LicenseeID", FLOWM2M_FLOW_OBJECT_LICENSEEID, \
		ResourceTypeEnum_TypeInteger, MandatoryEnum_Mandatory);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "LicenseeChallenge", FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE, \
		ResourceTypeEnum_TypeOpaque, MandatoryEnum_Optional);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "HashIterations", FLOWM2M_FLOW_OBJECT_HASHITERATIONS, \
		ResourceTypeEnum_TypeInteger, MandatoryEnum_Optional);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "LicenseeHash", FLOWM2M_FLOW_OBJECT_LICENSEEHASH, \
		ResourceTypeEnum_TypeOpaque, MandatoryEnum_Optional);
	REGISTER_FLOW_OBJECT_RESOURCE(context, "Status", FLOWM2M_FLOW_OBJECT_STATUS, \
		ResourceTypeEnum_TypeInteger, MandatoryEnum_Optional);

	return 0;
}

int Lwm2m_SetProvisioningInfo(Lwm2mContextType * context, const char * DeviceType,
	const char * FCAP, int64_t LicenseeID)
{
	CREATE_OBJECT_INSTANCE(context, FLOWM2M_FLOW_OBJECT, 0);

	if (Lwm2mCore_SetResourceInstanceValue(context, FLOWM2M_FLOW_OBJECT, 0,
		FLOWM2M_FLOW_OBJECT_FCAP, 0, FCAP, strlen(FCAP)) == -1)
	{
		Lwm2m_Error("Failed to set FCAP to %s\n", FCAP);
		return -1;
	}

	if (Lwm2mCore_SetResourceInstanceValue(context, FLOWM2M_FLOW_OBJECT, 0,
		FLOWM2M_FLOW_OBJECT_DEVICETYPE, 0, DeviceType, strlen(DeviceType)) == -1)
	{
		Lwm2m_Error("Failed to set Device Type to %s\n", DeviceType);
		return -1;
	}

	if (Lwm2mCore_SetResourceInstanceValue(context, FLOWM2M_FLOW_OBJECT, 0,
		FLOWM2M_FLOW_OBJECT_LICENSEEID, 0, &LicenseeID, sizeof(int64_t)) == -1)
	{
		Lwm2m_Error("Failed to set Licensee Id to %" PRId64 "\n", LicenseeID);
		return -1;
	}
	return 0;
}
