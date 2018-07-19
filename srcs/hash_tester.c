/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash_tester.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 12:51:07 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/19 13:05:57 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int			hash_tester(void *message
					   , uint32_t *to_test_digest
					   , uint64_t len
					   , t_system_hash_function hash_function)
{
		uint32_t	diff[8];

	hash_function(message, (unsigned int)len, (unsigned char*)diff);
	assert(sizeof(diff) == 32);
	if (ft_memcmp(to_test_digest, diff, sizeof(diff))) {
		print_memory(to_test_digest, 32);
		print_memory(diff, 32);
		printf("original string: \"%s\"\n", message);
		printf("my_hash:   %8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x\n", swap_int32(to_test_digest[0]), swap_int32(to_test_digest[1]), swap_int32(to_test_digest[2]), swap_int32(to_test_digest[3])
			   , swap_int32(to_test_digest[4]), swap_int32(to_test_digest[5]), swap_int32(to_test_digest[6]), swap_int32(to_test_digest[7]));
		printf("true_hash: %8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x\n", swap_int32(diff[0]), swap_int32(diff[1]), swap_int32(diff[2]), swap_int32(diff[3]), swap_int32(diff[4]), swap_int32(diff[5]), swap_int32(diff[6]), swap_int32(diff[7]));
		printf("FAILURE\n");
		return (0);
	}
	printf("%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x\n", swap_int32(to_test_digest[0]), swap_int32(to_test_digest[1]), swap_int32(to_test_digest[2]), swap_int32(to_test_digest[3])
		   , swap_int32(to_test_digest[4]), swap_int32(to_test_digest[5]), swap_int32(to_test_digest[6]), swap_int32(to_test_digest[7]));

	return (1);
}
