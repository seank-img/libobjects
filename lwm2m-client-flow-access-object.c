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
#include "common.h"

#include <awa/static.h>

/***************************************************************************************************
 * Definitions
 **************************************************************************************************/

#define FLOWM2M_FLOW_ACCESS_OBJECT								20001
#define FLOWM2M_FLOW_ACCESS_OBJECT_URL							0
#define FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY					1
#define FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET				2
#define FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN				3
#define FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY		4

#define FLOW_ACCESS_INSTANCES 1


typedef struct
{
	char URL[64];
	char CustomerKey[64];
	char CustomerSecret[64];
	char RememberMeToken[64];
	int8_t RememberMeTokenExpiry[16];
} FlowAccessObject;

FlowAccessObject flowAccess[FLOW_ACCESS_INSTANCES];

/***************************************************************************************************
 * Implementation - Public
 **************************************************************************************************/

AwaResult accessHandler(AwaStaticClient *client, AwaOperation operation, AwaObjectID objectID, AwaObjectInstanceID objectInstanceID,
	AwaResourceID resourceID, AwaResourceInstanceID resourceInstanceID, void **dataPointer, uint16_t *dataSize, bool *changed)
{
	AwaResult result = AwaResult_InternalError;

	if (!((objectID == FLOWM2M_FLOW_ACCESS_OBJECT) && (objectInstanceID >= 0) && (objectInstanceID < FLOW_ACCESS_INSTANCES)))
	{
		printf("incorrect flow access object data\n");
		return result;
	}

	switch (operation)
	{
		case AwaOperation_CreateObjectInstance:
			printf("flow access op - create object instance\n\n");
			result = AwaResult_SuccessCreated;
			memset(&flowAccess[objectInstanceID], 0, sizeof(flowAccess[objectInstanceID]));
			break;

		case AwaOperation_CreateResource:
			printf("flow access op - create resource %d\n", resourceID);
			result = AwaResult_SuccessCreated;
			break;

		case AwaOperation_Read:
			printf("flow access op - read for res %d\n", resourceID);
			switch (resourceID)
			{
				case 0:
					*dataPointer = flowAccess[objectInstanceID].URL;
					*dataSize = strlen(flowAccess[objectInstanceID].URL) + 1;
					result = AwaResult_SuccessCreated;
					break;

				case 1:
					*dataPointer = flowAccess[objectInstanceID].CustomerKey;
					*dataSize = strlen(flowAccess[objectInstanceID].CustomerKey) + 1;
					result = AwaResult_SuccessCreated;
					break;

				case 2:
					*dataPointer = flowAccess[objectInstanceID].CustomerSecret;
					*dataSize = strlen(flowAccess[objectInstanceID].CustomerSecret) + 1;
					result = AwaResult_SuccessCreated;
					break;

				case 3:
					*dataPointer = flowAccess[objectInstanceID].RememberMeToken;
					*dataSize = strlen(flowAccess[objectInstanceID].RememberMeToken) + 1;
					result = AwaResult_SuccessCreated;
					break;

				case 4:
					*dataPointer = flowAccess[objectInstanceID].RememberMeTokenExpiry;
					*dataSize = sizeof(flowAccess[objectInstanceID].RememberMeTokenExpiry);
					result = AwaResult_SuccessCreated;
					break;

				default:
					printf("\n invalid res id for flow access - read op");
					break;
			}
			break;

			case AwaOperation_Write:
				printf("flow acccess op - write for res %d\n", resourcId);
				switch (resourceID)
				{
					case 0:
						snprintf(flowAccess[objectInstanceID].URL, *dataSize, "%s", (char *)*dataPointer);
						*changed = true;
						result = AwaResult_SuccessCreated;
						break;

					case 1:
						snprintf(flowAccess[objectInstanceID].CustomerKey, *dataSize, "%s", (char *)*dataPointer);
						*changed = true;
						result = AwaResult_SuccessCreated;
						break;

					case 2:
						snprintf(flowAccess[objectInstanceID].CustomerSecret, *dataSize, "%s", (char *)*dataPointer);
						*changed = true;
						result = AwaResult_SuccessCreated;
						break;

					case 3:
						snprintf(flowAccess[objectInstanceID].RememberMeToken, *dataSize, "%s", (char *)*dataPointer);
						*changed = true;
						result = AwaResult_SuccessCreated;
						break;

					case 4:
						memcpy(flowAccess[objectInstanceID].RememberMeTokenExpiry, *dataPointer, *dataSize);
						*changed = true;
						result = AwaResult_SuccessCreated;
						break;

					default:
						printf("invalid res id %d for flow access - write op\n", resourceID);
						break;
				}
				break;

		default:
			printf("flow access - unknown operation\n");
			break;
	}
	return result;
}

int DefineFlowAccessObject(AwaStaticClient *awaClient)
{
	AwaError error;

	error = AwaStaticClient_DefineObjectWithHandler(awaClient, "FlowAccess", 20001, 0, FLOW_ACCESS_INSTANCES, accessHandler);
	if (error != AwaError_Success)
	{
		printf("Failed to register flow access object\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "URL", 20001, 0, AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite,
		accessHandler);
	if (error != AwaError_Success)
	{
		printf("Failed to define URL resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "CustomerKey",  20001, 1, AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite,
		accessHandler);
	if (error != AwaError_Success)
	{
		printf("Failed to define CustomerKey resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "CustomerSecret", 20001, 2, AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite,
		accessHandler);
	if (error != AwaError_Success)
	{
		printf("Failed to define CustomerSecret resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "RememberMeToken", 20001, 3, AwaResourceType_String, 0, 1, AwaResourceOperations_ReadWrite,
		accessHandler);
	if (error != AwaError_Success)
	{
		printf("Failed to define RememberMeToken resource\n");
		return 1;
	}

	error = AwaStaticClient_DefineResourceWithHandler(awaClient, "RememberMeTokenExpiry", 20001, 4, AwaResourceType_Opaque, 0, 1, AwaResourceOperations_ReadWrite,
		accessHandler);
	if (error != AwaError_Success)
	{
		printf("Failed to define RememberMeTokenExpiry resource\n");
		return 1;
	}

	return 0;
}

int CreateFlowAccessObject(AwaStaticClient *awaClient)
{
	AwaError error;

	error = AwaStaticClient_CreateObjectInstance(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, 0);
	if (error != AwaError_Success)
	{
		printf("failed to create flow access object instance\n");
		return 1;
	}

	error = AwaStaticClient_CreateResource(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, 0, FLOWM2M_FLOW_ACCESS_OBJECT_URL);
	if (error != AwaError_Success)
	{
		printf("failed to create URL resource\n");
		return 1;
	}
	error = AwaStaticClient_CreateResource(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, 0, FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERKEY);
	if (error != AwaError_Success)
	{
		printf("failed to create customer key resource\n");
		return 1;
	}
	error = AwaStaticClient_CreateResource(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, 0, FLOWM2M_FLOW_ACCESS_OBJECT_CUSTOMERSECRET);
	if (error != AwaError_Success)
	{
		printf("failed to create secret resource\n");
		return 1;
	}
	error = AwaStaticClient_CreateResource(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, 0, FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKEN);
	if (error != AwaError_Success)
	{
		printf("failed to create token resource\n");
		return 1;
	}
	error = AwaStaticClient_CreateResource(awaClient, FLOWM2M_FLOW_ACCESS_OBJECT, 0, FLOWM2M_FLOW_ACCESS_OBJECT_REMEMBERMETOKENEXPIRY);
	if (error != AwaError_Success)
	{
		printf("failed to create token expiry resource\n");
		return 1;
	}
	return 0;
}
