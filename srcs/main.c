/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/18 02:14:47 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/19 10:15:28 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <fcntl.h> //

int main(int argc, char **argv)
{
	if (argc == 2)
	{
		uint64_t len = strlen(argv[1]);
		uint32_t *digest = (uint32_t*)(void*)sha256_hash(argv[1], len);
		if (digest == NULL)
			return (EXIT_FAILURE);
		printf("%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x\n", swap_int32(digest[0])
			   , swap_int32(digest[1])
			   , swap_int32(digest[2])
			   , swap_int32(digest[3])
			   , swap_int32(digest[4])
			   , swap_int32(digest[5])
			   , swap_int32(digest[6])
			   , swap_int32(digest[7]));
		printf("%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x%8.8x\n", (digest[0])
			   , (digest[1])
			   , (digest[2])
			   , (digest[3])
			   , (digest[4])
			   , (digest[5])
			   , (digest[6])
			   , (digest[7]));
		/* if (!(md5_tester(argv[1], digest, len))) */
		/* 	exit(EXIT_FAILURE); */
	}
	else
	{
		md5_fuzzer();
//		ft_error_exit(1, (char*[]){"Unimplemented!()"}, 1);
	}
	return (0);
}
