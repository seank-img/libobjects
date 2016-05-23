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

/***************************************************************************************************
 * Definitions
 **************************************************************************************************/

#define FLOWM2M_FLOW_OBJECT                         20000
#define FLOWM2M_FLOW_OBJECT_DEVICEID                0
#define FLOWM2M_FLOW_OBJECT_PARENTID                1
#define FLOWM2M_FLOW_OBJECT_DEVICETYPE              2
#define FLOWM2M_FLOW_OBJECT_NAME                    3
#define FLOWM2M_FLOW_OBJECT_DESCRIPTION             4
#define FLOWM2M_FLOW_OBJECT_FCAP                    5
#define FLOWM2M_FLOW_OBJECT_LICENSEEID              6
#define FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE       7
#define FLOWM2M_FLOW_OBJECT_HASHITERATIONS          8
#define FLOWM2M_FLOW_OBJECT_LICENSEEHASH            9
#define FLOWM2M_FLOW_OBJECT_STATUS                  10

#define MAX_STRING_SIZE                             64
#define MAX_KEY_SIZE                                64



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
	int8_t ParentID[16];
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

static AwaResult FlowObjectResourceHandler(AwaStaticClient *client, AwaOperation operation, AwaObjectID objectID, AwaObjectInstanceID objectInstanceID,
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

        case AwaOperation_DeleteObjectInstance:
            result = AwaResult_SuccessDeleted;
            memset(&flow[objectInstanceID], 0, sizeof(FlowObject));
            break;

		case AwaOperation_CreateObjectInstance:
			result = AwaResult_SuccessCreated;
			memset(&flow[objectInstanceID], 0, sizeof(FlowObject));
			break;

		case AwaOperation_CreateResource:
			result = AwaResult_SuccessCreated;
			break;

		case AwaOperation_Read:
			switch (resourceID)
			{
				case FLOWM2M_FLOW_OBJECT_FCAP:
					*dataPointer = flow[objectInstanceID].FCAP;
					*dataSize = strlen(flow[objectInstanceID].FCAP);
					break;

				case FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE:
					*dataPointer = flow[objectInstanceID].LicenseeChallenge;
					*dataSize = flow[objectInstanceID].LicenseeChallengeSize;
					break;

				case FLOWM2M_FLOW_OBJECT_HASHITERATIONS:
					*dataPointer = &flow[objectInstanceID].HashIterations;
					*dataSize = sizeof(flow[objectInstanceID].HashIterations);
					break;

				case FLOWM2M_FLOW_OBJECT_LICENSEEHASH:
					*dataPointer = flow[objectInstanceID].LicenseeHash;
					*dataSize = flow[objectInstanceID].LicenseeHashSize;
					break;

				case FLOWM2M_FLOW_OBJECT_STATUS:
					*dataPointer = &flow[objectInstanceID].Status;
					*dataSize = sizeof(flow[objectInstanceID].Status);
					break;
				default:
					printf("[INFO] default case for read resource id %d\n", resourceID);
					break;
			}
			result = AwaResult_SuccessContent;
			break;

		case AwaOperation_Write:
			switch (resourceID)
			{
				case FLOWM2M_FLOW_OBJECT_FCAP:
				    memcpy(flow[objectInstanceID].FCAP, *dataPointer, *dataSize);
					flow[objectInstanceID].FCAP[*dataSize] = '\0';
					printf("[INFO] FCAP = %s\n", flow[objectInstanceID].FCAP);
					break;

				case FLOWM2M_FLOW_OBJECT_LICENSEEID:
					flow[objectInstanceID].LicenseeID =  (*(AwaInteger*)(*dataPointer));
					break;

				case FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE:
					memcpy(flow[objectInstanceID].LicenseeChallenge, *dataPointer, *dataSize);
					flow[objectInstanceID].LicenseeChallengeSize = *dataSize;
					break;

				case FLOWM2M_FLOW_OBJECT_HASHITERATIONS:
					flow[objectInstanceID].HashIterations = *((AwaInteger*)(*dataPointer));
					break;

				case FLOWM2M_FLOW_OBJECT_LICENSEEHASH:
					memcpy(flow[objectInstanceID].LicenseeHash, *dataPointer, *dataSize);
					flow[objectInstanceID].LicenseeHashSize = *dataSize;
					break;

				case FLOWM2M_FLOW_OBJECT_STATUS:
					flow[objectInstanceID].Status = *((AwaInteger*)(*dataPointer));
					printf("[INFO] Status: %li\n", flow[objectInstanceID].Status);
					*changed = true;
					break;

				default:
				    printf("[ERROR] Invalid write resource id %d\n", resourceID);
					break;
			}
			result = AwaResult_SuccessChanged;
			break;

		default:
			printf("[INFO] default case for handler, operation - %d\n", operation);
			break;
	}

	if(operation == AwaOperation_Write)
	{
        if(flow[objectInstanceID].HashIterations > 0 && flow[objectInstanceID].LicenseeChallengeSize > 0 && flow[objectInstanceID].LicenseeHashSize == 0
            && (resourceID == FLOWM2M_FLOW_OBJECT_HASHITERATIONS || (resourceID == FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE)))
        {
            printf("[INFO] Calculating licensee hash with %li iterations...\n", flow[objectInstanceID].HashIterations);

            if (CalculateLicenseeHash(licenseeSecret, flow[objectInstanceID].LicenseeHash, flow[objectInstanceID].LicenseeChallenge, flow[objectInstanceID].LicenseeChallengeSize, flow[objectInstanceID].HashIterations))
            {
                printf("[INFO] Calculated hash, writing Licensee Hash resource...\n");
                flow[objectInstanceID].LicenseeHashSize = SHA256_HASH_LENGTH;
                AwaStaticClient_CreateResource(client, FLOWM2M_FLOW_OBJECT, 0, FLOWM2M_FLOW_OBJECT_LICENSEEHASH);
                AwaStaticClient_ResourceChanged(client, FLOWM2M_FLOW_OBJECT, 0, FLOWM2M_FLOW_OBJECT_LICENSEEHASH);
            }
            else
            {
                printf("[ERROR] Licensee secret is invalid\n");
            }
        }
	}

	return result;
}

int DefineFlowObject(AwaStaticClient *awaClient)
{
	AwaStaticClient_DefineObject(awaClient, FLOWM2M_FLOW_OBJECT, "Flow", 0, FLOW_INSTANCES);
	AwaStaticClient_SetObjectOperationHandler(awaClient, FLOWM2M_FLOW_OBJECT, FlowObjectResourceHandler);

	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_DEVICEID,          "DeviceID",          AwaResourceType_Opaque,  1, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_DEVICEID,          flow[0].DeviceID, sizeof(flow[0].DeviceID), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_PARENTID,          "ParentID",          AwaResourceType_Opaque,  0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_PARENTID,          flow[0].ParentID, sizeof(flow[0].ParentID), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_DEVICETYPE,        "DeviceType",        AwaResourceType_String,  1, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_DEVICETYPE,        flow[0].DeviceType, sizeof(flow[0].DeviceType), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_NAME,              "Name",              AwaResourceType_String,  0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_NAME,              flow[0].Name, sizeof(flow[0].Name), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_DESCRIPTION,       "Description",       AwaResourceType_String,  0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_DESCRIPTION,       flow[0].Description, sizeof(flow[0].Description), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_FCAP,              "FCAP",              AwaResourceType_String,  1, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceOperationHandler(  awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_FCAP,              FlowObjectResourceHandler);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_LICENSEEID,        "LicenseeID",        AwaResourceType_Integer, 1, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceStorageWithPointer(awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_LICENSEEID,        &flow[0].LicenseeID, sizeof(flow[0].LicenseeID), 0);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE, "LicenseeChallenge", AwaResourceType_Opaque,  0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceOperationHandler(  awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_LICENSEECHALLENGE, FlowObjectResourceHandler);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_HASHITERATIONS,    "HashIterations",    AwaResourceType_Integer, 0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceOperationHandler(  awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_HASHITERATIONS,    FlowObjectResourceHandler);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_LICENSEEHASH,      "LicenseeHash",      AwaResourceType_Opaque,  0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceOperationHandler(  awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_LICENSEEHASH,      FlowObjectResourceHandler);
	AwaStaticClient_DefineResource(               awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_STATUS,            "Status",            AwaResourceType_Integer, 0, 1, AwaResourceOperations_ReadWrite);
	AwaStaticClient_SetResourceOperationHandler(  awaClient, FLOWM2M_FLOW_OBJECT, FLOWM2M_FLOW_OBJECT_STATUS,            FlowObjectResourceHandler);

	return 0;
}
