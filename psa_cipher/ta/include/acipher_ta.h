// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __ACIPHER_TA_H__
#define __ACIPHER_TA_H__

/* UUID of the acipher example trusted application */
#define TA_ACIPHER_UUID \
{ 0x7566754d, 0x6889, 0x4873, \
{ 0xb9, 0x4c, 0xea, 0xea, 0xdb, 0x7f, 0xf7, 0x95 } }

/*
 * in	params[0].value.a key size
 */
#define TA_ACIPHER_CMD_GEN_KEY		0

/*
 * in	params[1].memref  input
 * out	params[2].memref  output
 */
#define TA_ACIPHER_CMD_ENCRYPT		1

#endif /* __ACIPHER_TA_H */
