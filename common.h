/**
 * @file
 * LightWeightM2M Common definitions for libobjects.
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

#ifndef COMMON_H_
#define COMMON_H_

#define REGISTER_OBJECT(context, name, id, maxInstances, minInstances, handlers)                  \
	do                                                                                            \
	{                                                                                             \
		if (Lwm2mCore_RegisterObjectType(context, name, id, maxInstances, minInstances, handlers) \
			== -1)                                                                                \
		{                                                                                         \
			Lwm2m_Error("Failed to register object type for "name" object with Lwm2m core\n");    \
			return -1;                                                                            \
		}                                                                                         \
	}while(0)

#define REGISTER_RESOURCE(context, name, objId, id, type, maxInstances, minInstances, operations, \
	handlers)                                                                                     \
	do                                                                                            \
	{                                                                                             \
		if (Lwm2mCore_RegisterResourceType(context, name, objId, id, type, maxInstances,          \
			minInstances, operations, handlers) == -1)                                            \
			{                                                                                     \
				Lwm2m_Error("Failed to register "name" resource with Lwm2m core\n");              \
				return -1;                                                                        \
			}                                                                                     \
	}while(0)

#define CREATE_OBJECT_INSTANCE(context, objectId, objectInstanceId)                               \
	do                                                                                            \
	{                                                                                             \
		if (Lwm2mCore_CreateObjectInstance(context, objectId, objectInstanceId) == -1)            \
		{                                                                                         \
			Lwm2m_Error("Failed to create instance %d of "#objectId"\n", objectInstanceId);       \
			return -1;                                                                            \
		}                                                                                         \
	}while(0)

#define CREATE_OPTIONAL_RESOURCE(context, objectId, objectInstanceId, id)                         \
	do                                                                                            \
	{                                                                                             \
		if (Lwm2mCore_CreateOptionalResource(context, objectId, objectInstanceId, id) == -1)      \
		{                                                                                         \
			Lwm2m_Error("Failed to create optional "#id" for "#objectId" instance %d\n",          \
				objectInstanceID);                                                                \
			return -1;                                                                            \
		}                                                                                         \
	}while(0)

#endif
