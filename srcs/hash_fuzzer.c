/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash_fuzzer.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 12:54:34 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 22:09:47 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <fcntl.h>

static void	fuzzer_loop(t_hash_info *hash_info, int fd)
{
	char		*message;
	uint32_t	*digest;
	size_t		read_size;
	ssize_t		ret;
	uint64_t	len;

	read_size = rand() % MAX_RANDOM_MESSAGE_LEN;
	if (!(message = calloc(read_size + 1, 1)))
		exit(EXIT_FAILURE);
	if (-1 == (ret = read(fd, message, read_size)))
		exit(EXIT_FAILURE);
	assert((size_t)ret == read_size);
	len = (size_t)ret;
	printf("current message len: %llu\n", len);
	digest = (uint32_t*)(void*)hash_info->hash(message, len);
	if (digest == NULL)
		exit(EXIT_FAILURE);
	if (!(hash_tester(message, digest, len, hash_info)))
		exit(EXIT_FAILURE);
	print_hash(digest, hash_info->digest_size, 1);
	printf("\n");
	free(message);
}

NORETURN	hash_fuzzer(t_hash_info *hash_info)
{
	int fd;

	srand(RANDOM_INIT);
	if (-1 == (fd = open("/dev/random", O_RDONLY)))
		exit(EXIT_FAILURE);
	while (1)
		fuzzer_loop(hash_info, fd);
}
