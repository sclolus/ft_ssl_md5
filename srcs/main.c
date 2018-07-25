/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/18 02:14:47 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 02:42:04 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <fcntl.h> //
#include <CommonCrypto/CommonDigest.h>

const t_hash_identity	g_supported_hashs[SUPPORTED_TYPES] = {
	{"md5", parse_md5, md5_hash, CC_MD5, md5_cmd_exec, 4 * 4, MD5, {0}},
	{"sha256", parse_sha256, sha256_hash, CC_SHA256, sha256_cmd_exec, 8 * 4, SHA256, {0}},
	{"sha224", parse_sha256, sha224_hash, CC_SHA224, sha256_cmd_exec, 7 * 4, SHA224, {0}},
}; // should do something about those extra fields

int main(int argc, char **argv)
{
	t_command_line	*cmd;

	cmd = parse_command_line(argc, argv);
	if (argc != 1)
	{
		exec_cmd(cmd);
		/* uint64_t len = strlen(argv[1]); */
		/* uint32_t *digest = (uint32_t*)(void*)sha256_hash(argv[1], len); */
		/* if (digest == NULL) */
		/* 	return (EXIT_FAILURE); */
		/* uint32_t diff[8]; */
		/* CC_SHA256(argv[1], (unsigned int)len, (unsigned char*)diff); */
		/* print_memory(digest, 32); */
		/* printf("----\n"); */
		/* print_memory(diff, 32); */
		/* printf("%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x\n", (digest[0]) */
		/* 	   , (digest[1]) */
		/* 	   , (digest[2]) */
		/* 	   , (digest[3]) */
		/* 	   , (digest[4]) */
		/* 	   , (digest[5]) */
		/* 	   , (digest[6]) */
		/* 	   , (digest[7])); */
		/* printf("%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x\n", (diff[0]) */
		/* 	   , (diff[1]) */
		/* 	   , (diff[2]) */
		/* 	   , (diff[3]) */
		/* 	   , (diff[4]) */
		/* 	   , (diff[5]) */
		/* 	   , (diff[6]) */
		/* 	   , (diff[7])); */
	}
	else
	{
		hash_fuzzer(&(t_hash_info){CC_SHA224, sha224_hash, 7 * 4});
//		hash_fuzzer(&(t_hash_info){CC_SHA256, sha256_hash, 8 * 4});
//		hash_fuzzer(&(t_hash_info){CC_MD5, md5_hash, 4 * 4});
	}
}
