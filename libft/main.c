/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/12/17 17:58:15 by sclolus           #+#    #+#             */
/*   Updated: 2018/01/09 08:08:53 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <libkern/OSByteOrder.h>

int	main(void)
{
	uint64_t	i;

	i = 0;
//	printf("i: %u, expected end: %llu\n", i, (uint64_t)~0UL);
	while (i < (uint64_t)~0ULL)
	{
//		printf("Test: %u OK\n", i);
		if (swap_int64(i) != OSSwapInt64(i))
		{
			printf("Test Failure: KO\n");
			exit(EXIT_FAILURE);
		}
		i++;
		if (i == (uint64_t)~0ULL)
			break;
	}
	printf("Success: OK\n");
	return (0);
}
