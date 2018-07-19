/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/18 02:14:47 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/19 04:21:32 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <fcntl.h> //

int main(int argc, char **argv)
{
	if (argc == 2)
	{
		uint64_t len = strlen(argv[1]);
		uint32_t *digest = (uint32_t*)(void*)md5_hash(argv[1], len);
		if (digest == NULL)
			return (EXIT_FAILURE);
		if (!(md5_tester(argv[1], digest, len)))
			exit(EXIT_FAILURE);
	}
	else
	{
		md5_fuzzer();
//		ft_error_exit(1, (char*[]){"Unimplemented!()"}, 1);
	}
	return (0);
}
