/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash_tester.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 12:51:07 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 22:13:51 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int			hash_tester(void *message
						, uint32_t *to_test_digest
						, uint64_t len
						, t_hash_info *hash_info)
{
	uint32_t	diff[128];

	assert(sizeof(diff) >= hash_info->digest_size);
	hash_info->system_hash(message, (unsigned int)len, (unsigned char*)diff);
	if (ft_memcmp(to_test_digest, diff, hash_info->digest_size))
	{
		printf("------>digest memory\n");
		print_memory(to_test_digest, hash_info->digest_size);
		printf("------>true digest memory\n");
		print_memory(diff, hash_info->digest_size);
		printf("\noriginal string: \"%s\"\n", message);
		printf("my_hash:  ");
		print_hash(to_test_digest, hash_info->digest_size, 1);
		printf("\n");
		print_hash(diff, hash_info->digest_size, 1);
		printf("\n");
		printf("true_hash:  ");
		printf("FAILURE\n");
		return (0);
	}
	return (1);
}
