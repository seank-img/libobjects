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
#include <awa/static.h>
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



/***************************************************************************************************
 * Globals
 **************************************************************************************************/

#define FLOW_INSTANCES 1
static char licenseeSecret[64] = "getATTtDsNBpBRnMsN7GoQ==";


/***************************************************************************************************
 * Implementation - Public
 **************************************************************************************************/
typedef struct
{
	int8_t DeviceID[16];
	size_t DeviceIDSize;
	int8_t ParentID[16];
	size_t ParentIDSize;
	char DeviceType[64];
	char Name[64];
	char Description[64];
	char FCAP[64];
	AwaInteger LicenseeID;
	uint8_t LicenseeChallenge[64];
	size_t LicenseeChallengeSize;
	AwaInteger HashIterations;
	uint8_t LicenseeHash[SHA256_HASH_LENGTH];
	size_t LicenseeHashSize;
	AwaInteger Status;
} FlowObject;

static FlowObject flow[FLOW_INSTANCES] = {0};

static bool CalculateLicenseeHash(char *licenseeSecret, uint8_t hash[SHA256_HASH_LENGTH], const char *challenge, int challengeLength, int iterations)
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

AwaResult handler(AwaStaticClient *client, AwaOperation operation, AwaObjectID objectID, AwaObjectInstanceID objectInstanceID,
	AwaResourceID resourceID, AwaResourceInstanceID resourceInstanceID, void **dataPointer, size_t *dataSize, bool *changed)
{
	AwaResult result = AwaResult_InternalError;

	if (!((objectID == FLOWM2M_FLOW_OBJECT) && (objectInstanceID >= 0) && (objectInstanceID < FLOW_INSTANCES)))
	{
		printf("incorrect flow object data\n");
		return result;
	}

	switch (operation)
	{
		case AwaOperation_CreateObjectInstance:
			printf("flow op - create object instance\n\n");
			result = AwaResult_SuccessCreated;
			memset(&flow[objectInstanceID], 0, sizeof(FlowObject));
			break;

		case AwaOperation_CreateResource:
			printf("flow op - create resource %d\n", resourceID);

			result = AwaResult_SuccessCreated;
			break;

		case AwaOperation_Read:
			printf("flow op - read for res %d\n", resourceID);
			switch (resourceID)
			{
				case 0:
					*dataPointer = flow[objectInstanceID].DeviceID;
					*dataSize = flow[objectInstanceID].DeviceIDSize;
					break;

				case 1:
					*dataPointer = flow[objectInstanceID].ParentID;
					*dataSize = flow[objectInstanceID].ParentIDSize;
					break;

				case 2:
					*dataPointer = flow[objectInstanceID].DeviceType;
					*dataSize = strlen(flow[objectInstanceID].DeviceType);
					break;

				case 3:
					*dataPointer = flow[objectInstanceID].Name;
					*dataSize = strlen(flow[objectInstanceID].Name);
					break;

				case 4:
					*dataPointer = flow[objectInstanceID].Description;
					*dataSize = strlen(flow[objectInstanceID].Description);
					break;

				case 5:
					*dataPointer = flow[objectInstanceID].FCAP;
					*dataSize = strlen(flow[objectInstanceID].FCAP);
					break;

				case 6:
					*dataPointer = &flow[objectInstanceID].LicenseeID;
					*dataSize = sizeof(flow[objectInstanceID].LicenseeID);
					break;

				case 7:
					*dataPointer = flow[objectInstanceID].LicenseeChallenge;
					*dataSize = flow[objectInstanceID].LicenseeChallengeSize;
					break;

				case 8:
					*dataPointer = &flow[objectInstanceID].HashIterations;
					*dataSize = sizeof(flow[objectInstanceID].HashIterations);
					break;

				case 9:
					*dataPointer = flow[objectInstanceID].LicenseeHash;
					*dataSize = flow[objectInstanceID].LicenseeHashSize;
					break;

				case 10:
					*dataPointer = &flow[objectInstanceID].Status;
					*dataSize = sizeof(flow[objectInstanceID].Status);
					break;

				default:
					printf("Invalid resource id\n");
			}
			result = AwaResult_SuccessContent;
			break;

		case AwaOperation_Write:
			printf("flow op - write for res %d\n", resourceID);
			switch (resourceID)
			{
				case 0:
					memcpy(flow[objectInstanceID].DeviceID, *dataPointer, *dataSize);
					*changed = true;
					break;

				case 1:
					memcpy(flow[objectInstanceID].ParentID, *dataPointer, *dataSize);
					*changed = true;
					break;

				case 2:
					memcpy(flow[objectInstanceID].DeviceType, *dataPointer, *dataSize);
					flow[objectInstanceID].DeviceType[*dataSize] = '\0';
					*changed = true;
					break;

				case 3:
				    memcpy(flow[objectInstanceID].Name, *dataPointer, *dataSize);
				    flow[objectInstanceID].Name[*dataSize] = '\0';
					*changed = true;
					break;

				case 4:
					memcpy(flow[objectInstanceID].Description,  *dataPointer, *dataSize);
					flow[objectInstanceID].Description[*dataSize] = '\0';
					*changed = true;
					break;

				case 5:
				    memcpy(flow[objectInstanceID].FCAP, *dataPointer, *dataSize);
					flow[objectInstanceID].FCAP[*dataSize] = '\0';
					printf("FCAP = %s\n", flow[objectInstanceID].FCAP);
					*changed = true;
					break;

				case 6:
					flow[objectInstanceID].LicenseeID =  (*(AwaInteger*)(*dataPointer));
					printf("LicenseeID: %d %d\n", flow[objectInstanceID].LicenseeID, *dataSize);
					*changed = true;
					break;

				case 7:
					memcpy(flow[objectInstanceID].LicenseeChallenge, *dataPointer, *dataSize);
					*changed = true;
					break;

				case 8:
					flow[objectInstanceID].HashIterations = *((AwaInteger*)(*dataPointer));
					*changed = true;
					break;

				case 9:
					memcpy(flow[objectInstanceID].LicenseeHash, *dataPointer, *dataSize);
					*changed = true;
					break;

				case 10:
					flow[objectInstanceID].Status = *((AwaInteger*)(*dataPointer));
					*changed = true;
					break;

				default:
					printf("invalid resource id for write operation\n");
					break;
			}
			result = AwaResult_SuccessChanged;
			break;

		default:
			printf("default case for handler, operation - %d\n", operation);
			break;
	}

	if(flow[objectInstanceID].HashIterations > 0 && flow[objectInstanceID].LicenseeChallenge != NULL
		&& (resourceID == FLOWM2M_FLOW_OBJECT_HASHITERATIONS || (resourceID == FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE)))
	{
		uint8_t licenseeHash[SHA256_HASH_LENGTH];

		printf("Calculating licensee hash with %d iterations...\n", flow[objectInstanceID].HashIterations);

		if (CalculateLicenseeHash(licenseeSecret, licenseeHash, flow[objectInstanceID].LicenseeChallenge, 64,
			flow[objectInstanceID].HashIterations))
		{
			printf("Calculated hash, writing Licensee Hash resource...\n");
			memcpy(flow[objectInstanceID].LicenseeHash, licenseeHash, SHA256_HASH_LENGTH);
			result = AwaStaticClient_ResourceChanged(client, FLOWM2M_FLOW_OBJECT, 0, FLOWM2M_FLOW_OBJECT_LICENSEEHASH);
		}
		else
		{
			printf("Licensee secret is invalid\n");
			return AwaResult_InternalError;
		}
	}

	return result;
}

int DefineFlowObject(AwaStaticClient *awaClient)
{
	AwaError error;

	error = AwaStaticClient_DefineObjectWithHandler(awaClient, "Flow", 20000, 0, FLOW_INSTANCES, handler);
	if (error != AwaError_Success)
	{
		printf("Failed to register flow bject\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "DeviceID", 20000, 0, AwaResourceType_Opaque, 0, 1, AwaResourceOperations_ReadWrite,
	handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define deviceID resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "ParentID",  20000, 1, AwaResourceType_Opaque, 0, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define parentID resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "DeviceType", 20000, 2, AwaResourceType_String, 1, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define device type resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "Name", 20000, 3, AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define name resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "Description", 20000, 4, AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define description resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "FCAP", 20000, 5, AwaResourceType_String, 1, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define FCAP resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "LicenseeID", 20000, 6, AwaResourceType_Integer, 1, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define LicenseeID resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "LicenseeChallenge", 20000, 7, AwaResourceType_Opaque, 0, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define LicenseeChallenge resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "HashIterations", 20000, 8, AwaResourceType_Integer, 0, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define HashIterations resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "LicenseeHash", 20000, 9, AwaResourceType_Opaque, 0, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define LicenseeHash resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "Status", 20000, 10, AwaResourceType_Integer, 0, 1, AwaResourceOperations_ReadWrite,
		handler);
	if (error != AwaError_Success)
	{
		printf("Failed to define Status resource\n");
		return 1;
	}

	return 0;
}
