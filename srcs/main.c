/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/18 02:14:47 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 21:48:04 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <fcntl.h> //
#include <CommonCrypto/CommonDigest.h>

const t_cmd_identity	g_supported_cmds[SUPPORTED_TYPES] = {
	{"md5", parse_md5, md5_cmd_exec, (t_cmd_internal){(t_hash_identity){md5_hash, CC_MD5, 4 * 4}}, MD5, HASH},
	{"sha256", parse_sha256, sha256_cmd_exec, (t_cmd_internal){(t_hash_identity){sha256_hash, CC_SHA256, 8 * 4}}, SHA256, HASH},
	{"sha224", parse_sha256, sha256_cmd_exec, (t_cmd_internal){(t_hash_identity){sha224_hash, CC_SHA224, 7 * 4}}, SHA224, HASH},
	{"md5", parse_md5, md5_cmd_exec, (t_cmd_internal){(t_hash_identity){md5_hash, CC_MD5, 4 * 4}}, MD5, HASH},
	{"base64", parse_base64, base64_cmd_exec, (t_cmd_internal){.se = {encode_base64, decode_base64}}, BASE64, SYMMETRIC_ENCRYPTION},
	{"des", parse_des, des_cmd_exec, (t_cmd_internal){.se = {encode_des, decode_des}}, DES, SYMMETRIC_ENCRYPTION},
};

/* const t_hash_identity	g_supported_hashs[SUPPORTED_TYPES] = { */
/* 	{"md5", parse_md5, md5_hash, CC_MD5, md5_cmd_exec, 4 * 4, MD5, {0}}, */
/* 	{"sha256", parse_sha256, sha256_hash, CC_SHA256, sha256_cmd_exec, 8 * 4 */
/* 	, SHA256, {0}}, */
/* 	{"sha224", parse_sha256, sha224_hash, CC_SHA224, sha256_cmd_exec, 7 * 4 */
/* 	, SHA224, {0}}, //same exec and cmd_parse functions, it's okay now, but hey should change that */
/* 	{"sha512", parse_sha256, (t_hash_function)sha512_hash, CC_SHA512 */
/* 	, sha256_cmd_exec, 8 * 8, SHA512, {0}}, //same exec and cmd_parse functions, it's okay now, but hey should change that */
/* }; // should do something about those extra fields */

int	main(int argc, char **argv)
{
	t_command_line	*cmd;

	cmd = parse_command_line(argc, argv);
	if (argc != 1)
	{
		exec_cmd(cmd);
	}
	else
	{
		/* hash_fuzzer(&(t_hash_info){CC_SHA512, (t_hash_function)sha512_hash */
		/* 			, 7 * 4}); */
//		hash_fuzzer(&(t_hash_info){CC_MD5, md5_hash, 4 * 4});
		hash_fuzzer(&(t_hash_info){CC_SHA256, sha256_hash, 8 * 4});
	}
}
/*		hash_fuzzer(&(t_hash_info){CC_SHA224, sha224_hash, 7 * 4});
**		hash_fuzzer(&(t_hash_info){CC_SHA256, sha256_hash, 8 * 4});
**		hash_fuzzer(&(t_hash_info){CC_MD5, md5_hash, 4 * 4});
*/
