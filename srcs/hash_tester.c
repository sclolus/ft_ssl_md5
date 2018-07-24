/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash_tester.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 12:51:07 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/24 22:34:35 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static void	print_hash(uint32_t *digest, uint64_t size)
{
	uint32_t	i;

	i = 0;
	while (i < size / 4)
	{
		printf("%8.8x", (digest[i]));
		i++;
	}
	printf("\n");
}

int			hash_tester(void *message
					   , uint32_t *to_test_digest
					   , uint64_t len
					   , t_hash_info *hash_info)
{
	uint32_t	diff[128]; //just some maximum hash size

	hash_info->system_hash(message, (unsigned int)len, (unsigned char*)diff);
	if (ft_memcmp(to_test_digest, diff, hash_info->digest_size)) {
		print_memory(to_test_digest, hash_info->digest_size);
		print_memory(diff, hash_info->digest_size);
		printf("original string: \"%s\"\n", message);
		printf("my_hash:  ");
		print_hash(to_test_digest, hash_info->digest_size);
		print_hash(diff, hash_info->digest_size);
		printf("true_hash:  ");
		printf("FAILURE\n");
		return (0);
	}
	print_hash(to_test_digest, hash_info->digest_size);
	return (1);
}
