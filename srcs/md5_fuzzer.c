/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_fuzzer.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 04:11:02 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/19 04:22:41 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <fcntl.h>


NORETURN	md5_fuzzer(void) {
	srand(RANDOM_INIT);
	int fd;
	if (-1 == (fd = open("/dev/random", O_RDONLY)))
		exit (EXIT_FAILURE);
	while (1) {
		size_t read_size = rand() % MAX_RANDOM_MESSAGE_LEN;
		char *message;

		if (!(message = calloc(read_size + 1, 1)))
			exit (EXIT_FAILURE);
		ssize_t ret;
		if (-1 == (ret = read(fd, message, read_size)))
			exit (EXIT_FAILURE);
		assert((size_t)ret == read_size);
		uint64_t len = strlen(message);
		uint32_t *digest = (uint32_t*)(void*)md5_hash(message, len);
		if (digest == NULL)
			exit (EXIT_FAILURE);
		if (!(md5_tester(message, digest, len)))
			exit(EXIT_FAILURE);
		free(message);
	}
}
