// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

/* BINARY_PREFIX is expected by teec_trace.h */
#ifndef BINARY_PREFIX
#define BINARY_PREFIX		"ckteec"
#endif

#include <errno.h>
#include <inttypes.h>
#include <pkcs11.h>
#include <pkcs11_ta.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <tee_client_api.h>
#include <teec_trace.h>
#include <unistd.h>

#include "ck_helpers.h"
#include "invoke_ta.h"
#include "local_utils.h"

#define CLIENT_SALT_SIZE	16

struct ta_context {
	pthread_mutex_t init_mutex;
	bool initiated;
	TEEC_Context context;
	TEEC_Session session;
};

static struct ta_context ta_ctx = {
	.init_mutex = PTHREAD_MUTEX_INITIALIZER,
};

bool ckteec_invoke_initiated(void)
{
	return ta_ctx.initiated;
}

TEEC_SharedMemory *ckteec_alloc_shm(size_t size, enum ckteec_shm_dir dir)
{
	TEEC_SharedMemory *shm = NULL;

	switch (dir) {
	case CKTEEC_SHM_IN:
	case CKTEEC_SHM_OUT:
	case CKTEEC_SHM_INOUT:
		break;
	default:
		return NULL;
	}

	shm = calloc(1, sizeof(TEEC_SharedMemory));
	if (!shm)
		return NULL;

	shm->size = size;

	if (dir == CKTEEC_SHM_IN || dir == CKTEEC_SHM_INOUT)
		shm->flags |= TEEC_MEM_INPUT;
	if (dir == CKTEEC_SHM_OUT || dir == CKTEEC_SHM_INOUT)
		shm->flags |= TEEC_MEM_OUTPUT;

	if (TEEC_AllocateSharedMemory(&ta_ctx.context, shm)) {
		free(shm);
		return NULL;
	}

	return shm;
}

TEEC_SharedMemory *ckteec_register_shm(void *buffer, size_t size,
				       enum ckteec_shm_dir dir)
{
	TEEC_SharedMemory *shm = NULL;

	switch (dir) {
	case CKTEEC_SHM_IN:
	case CKTEEC_SHM_OUT:
	case CKTEEC_SHM_INOUT:
		break;
	default:
		return NULL;
	}

	shm = calloc(1, sizeof(TEEC_SharedMemory));
	if (!shm)
		return NULL;

	shm->buffer = buffer;
	shm->size = size;

	if (dir == CKTEEC_SHM_IN || dir == CKTEEC_SHM_INOUT)
		shm->flags |= TEEC_MEM_INPUT;
	if (dir == CKTEEC_SHM_OUT || dir == CKTEEC_SHM_INOUT)
		shm->flags |= TEEC_MEM_OUTPUT;

	if (TEEC_RegisterSharedMemory(&ta_ctx.context, shm)) {
		free(shm);
		return NULL;
	}

	return shm;
}

void ckteec_free_shm(TEEC_SharedMemory *shm)
{
	TEEC_ReleaseSharedMemory(shm);
	free(shm);
}

static bool is_output_shm(TEEC_SharedMemory *shm)
{
	return shm && (shm->flags & TEEC_MEM_OUTPUT);
}

CK_RV ckteec_invoke_ta(unsigned long cmd, TEEC_SharedMemory *ctrl,
		       TEEC_SharedMemory *io1,
		       TEEC_SharedMemory *io2, size_t *out2_size,
		       TEEC_SharedMemory *io3, size_t *out3_size)
{
	uint32_t command = (uint32_t)cmd;
	TEEC_Operation op;
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ta_rc = PKCS11_CKR_GENERAL_ERROR;

	if ((is_output_shm(io2) && !out2_size) ||
	    (is_output_shm(io3) && !out3_size))
		return CKR_ARGUMENTS_BAD;

	memset(&op, 0, sizeof(op));

	if (ctrl && !(ctrl->flags & TEEC_MEM_INPUT &&
		      ctrl->flags & TEEC_MEM_OUTPUT))
		return CKR_ARGUMENTS_BAD;

	if (ctrl) {
		op.paramTypes |= TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, 0, 0, 0);
		op.params[0].memref.parent = ctrl;
	} else {
		/* TA mandates param#0 as in/out memref for output status */
		op.paramTypes |= TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						  0, 0, 0);
		op.params[0].tmpref.buffer = &ta_rc;
		op.params[0].tmpref.size = sizeof(ta_rc);
	}

	if (io1) {
		op.paramTypes |= TEEC_PARAM_TYPES(0, TEEC_MEMREF_WHOLE, 0, 0);
		op.params[1].memref.parent = io1;
	}

	if (io2) {
		op.paramTypes |= TEEC_PARAM_TYPES(0, 0, TEEC_MEMREF_WHOLE, 0);
		op.params[2].memref.parent = io2;
	}

	if (io3) {
		op.paramTypes |= TEEC_PARAM_TYPES(0, 0, 0, TEEC_MEMREF_WHOLE);
		op.params[3].memref.parent = io3;
	}

	res = TEEC_InvokeCommand(&ta_ctx.session, command, &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
		/* Get PKCS11 TA return value from ctrl buffer */
		if (ctrl) {
			if (op.params[0].memref.size == sizeof(ta_rc))
				memcpy(&ta_rc, ctrl->buffer, sizeof(ta_rc));
		} else {
			if (op.params[0].tmpref.size != sizeof(ta_rc))
				ta_rc = PKCS11_CKR_GENERAL_ERROR;
		}
		break;
	case TEEC_ERROR_SHORT_BUFFER:
		ta_rc = CKR_BUFFER_TOO_SMALL;
		break;
	case TEEC_ERROR_OUT_OF_MEMORY:
		return CKR_DEVICE_MEMORY;
	default:
		return CKR_GENERAL_ERROR;
	}

	if (ta_rc == CKR_OK || ta_rc == CKR_BUFFER_TOO_SMALL) {
		if (is_output_shm(io2))
			*out2_size = op.params[2].memref.size;
		if (is_output_shm(io3))
			*out3_size = op.params[3].memref.size;
	}

	return ta_rc;
}

static CK_RV ping_ta(void)
{
	TEEC_Operation op = { 0 };
	uint32_t origin = 0;
	TEEC_Result res = TEEC_SUCCESS;
	uint32_t ta_version[3] = { 0 };
	uint32_t status = 0;

	memset(&op, 0, sizeof(op));
	op.params[0].tmpref.buffer = &status;
	op.params[0].tmpref.size = sizeof(status);
	op.params[2].tmpref.buffer = ta_version;
	op.params[2].tmpref.size = sizeof(ta_version);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&ta_ctx.session, PKCS11_CMD_PING, &op,
				 &origin);

	if (res != TEEC_SUCCESS ||
	    origin != TEEC_ORIGIN_TRUSTED_APP ||
	    op.params[0].tmpref.size != sizeof(status) ||
	    status != PKCS11_CKR_OK)
		return CKR_DEVICE_ERROR;

	if (ta_version[0] != PKCS11_TA_VERSION_MAJOR &&
	    ta_version[1] > PKCS11_TA_VERSION_MINOR) {
		EMSG("PKCS11 TA version mismatch: %"PRIu32".%"PRIu32".%"PRIu32,
		     ta_version[0], ta_version[1], ta_version[2]);

		return CKR_DEVICE_ERROR;
	}

	DMSG("PKCS11 TA version %"PRIu32".%"PRIu32".%"PRIu32,
	     ta_version[0], ta_version[1], ta_version[2]);

	return CKR_OK;
}

CK_RV ckteec_invoke_init(void)
{
	TEEC_UUID uuid = PKCS11_TA_UUID;
	uint32_t origin = 0;
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Operation op = { };
	CK_RV rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
	int e = 0;
	size_t i = 0;

	union random
	{
		int int_arr[CLIENT_SALT_SIZE / sizeof(int)];
		char char_arr[CLIENT_SALT_SIZE];
	} random = { };

	struct login_session {
		uint32_t method;
		const char *method_as_str;
	} login_sessions[] = {
		{ TEEC_LOGIN_USER, "TEEC_LOGIN_USER" },
		{ TEEC_LOGIN_APPLICATION, "TEEC_LOGIN_APPLICATION" },
		{ TEEC_LOGIN_USER_APPLICATION, "TEEC_LOGIN_USER_APPLICATION" },
	};

	e = pthread_mutex_lock(&ta_ctx.init_mutex);
	if (e)
		return CKR_CANT_LOCK;

	if (ta_ctx.initiated) {
		rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
		goto out;
	}

	res = TEEC_InitializeContext(NULL, &ta_ctx.context);
	if (res != TEEC_SUCCESS) {
		EMSG("TEEC init context failed\n");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	/*
	 * Generate random bytes for this client.
	 * This can help to identify current client, when logic with
	 * calculating several CA_UUIDs is still in progress (see below).
	 *
	 * This can protect a CA if any malicious client communicates
	 * in a way that bypasses libckteec.
	 */
	srand(time(NULL));
	COMPILE_TIME_ASSERT((CLIENT_SALT_SIZE % sizeof(int)) == 0);
	for (i = 0; i < CLIENT_SALT_SIZE / sizeof(int); ++i)
		random.int_arr[i] = rand();

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, 0, 0, 0);
	op.params[0].tmpref.buffer = random.char_arr;
	op.params[0].tmpref.size = CLIENT_SALT_SIZE;

	/*
	 * Every CAs must have the ability to create own keys, certificates or
	 * data in own token. TA must create tokens for this particular CA opening a
	 * tee session, if they don't exist.

	 * Every CA has three tokens:
	 * - "USER" - data in this token are shared between all application
	 *            for a particular user.
	 * - "APPLICATION" - data in this token are accessed only for a particaular CA, 
	 *                   but shared between all users.
	 * - "USER+APPLICATION" - data in this token are accessed only for a particular
	 *                        couple user+app.

	 * Every token in the pkcs11-ta has an own name for persistent object in secure
	 * storage based on calculated CA_UUID:
	 * - Token "USER" has <ca-uuid-based-on-USER-login-method>.
	 * - Token "APPLICATION" has <ca-uuid-based-on-APP-login-method>.
	 * - Token "USER+APPLICATION" has "token.<ca-uuid-based-on-USERAPP-login-method>".
	 * These names are used by the TA to have an access to token persistent file in
	 * seruce storage. C_GetSlotList() will return slots with tokens are available
	 * only for particular CA. 

	 * To make this logic available, it is needed to open several tee-sessions
	 * one after another with different login methods. If TA returns "OK",
	 * then to close session. It means TA successfully has created a token
	 * or this token alredy exists.

	 * Last session is opened with <TEEC_LOGIN_USER_APPLICATION> method and isn't closed.
	 * CA will use this session to interact with TA. 
	 */

	for (i = 0; i < ARRAY_SIZE(login_sessions); ++i) {
		res = TEEC_OpenSession(&ta_ctx.context, &ta_ctx.session, &uuid,
			login_sessions[i].method, NULL, &op, &origin);
		if (res == TEEC_SUCCESS) {
			if (login_sessions[i].method !=
					TEEC_LOGIN_USER_APPLICATION)
				TEEC_CloseSession(&ta_ctx.session);
		} else {
			EMSG("TEEC open session with <%s> failed %x from %d\n",
			     login_sessions[i].method_as_str, res, origin);
			TEEC_FinalizeContext(&ta_ctx.context);
			rv = CKR_DEVICE_ERROR;
			goto out;
		}
	}

	rv = ping_ta();

	if (rv == CKR_OK) {
		ta_ctx.initiated = true;
	} else {
		TEEC_CloseSession(&ta_ctx.session);
		TEEC_FinalizeContext(&ta_ctx.context);
	}

out:
	e = pthread_mutex_unlock(&ta_ctx.init_mutex);
	if (e) {
		EMSG("pthread_mutex_unlock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}

	return rv;
}

CK_RV ckteec_invoke_terminate(void)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	int e = 0;

	e = pthread_mutex_lock(&ta_ctx.init_mutex);
	if (e) {
		EMSG("pthread_mutex_lock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}

	if (!ta_ctx.initiated)
		goto out;

	ta_ctx.initiated = false;
	TEEC_CloseSession(&ta_ctx.session);
	TEEC_FinalizeContext(&ta_ctx.context);

	rv = CKR_OK;

out:
	e = pthread_mutex_unlock(&ta_ctx.init_mutex);
	if (e) {
		EMSG("pthread_mutex_unlock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}

	return rv;
}
