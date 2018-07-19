/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_tester.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 04:12:19 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/19 09:51:01 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <CommonCrypto/CommonDigest.h>
#include "ft_ssl_md5.h"


INLINE int	md5_tester(void *message, uint32_t *to_test_digest, uint64_t len)
{
	uint32_t	diff[4];

	CC_MD5(message, (unsigned int)len, (unsigned char*)diff);
	assert(sizeof(diff) == 16);
	if (ft_memcmp(to_test_digest, diff, sizeof(diff))) {
		print_memory(to_test_digest, 16);
		print_memory(diff, 16);
		printf("original string: \"%s\"\n", message);
		printf("my_hash:   %8.8x%8.8x%8.8x%8.8x\n", swap_int32(to_test_digest[0]), swap_int32(to_test_digest[1]), swap_int32(to_test_digest[2]), swap_int32(to_test_digest[3]));
		printf("true_hash: %8.8x%8.8x%8.8x%8.8x\n", swap_int32(diff[0]), swap_int32(diff[1]), swap_int32(diff[2]), swap_int32(diff[3]));
		printf("FAILURE\n");
		return (0);
	}
	printf("%8.8x%8.8x%8.8x%8.8x\n", swap_int32(to_test_digest[0]), swap_int32(to_test_digest[1]), swap_int32(to_test_digest[2]), swap_int32(to_test_digest[3]));
	return (1);
}
