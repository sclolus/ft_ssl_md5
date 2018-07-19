/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_md5.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/18 01:54:31 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/19 05:11:52 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_MD5
# define FT_SSL_MD5

# include "libft.h"
# include <stdio.h> //
# include <unistd.h>
# include <stdlib.h>
# include <assert.h> //

# define INLINE __attribute__((always_inline)) inline
# define NORETURN __attribute__((noreturn)) void

void		print_memory(const void *addr, size_t size);


/*
** Hash functions
*/

uint32_t	*md5_hash(void *clear, uint64_t len);


/*
** Hash testers
*/

# define MAX_RANDOM_MESSAGE_LEN 4096
# define RANDOM_INIT 0xBADA55

NORETURN	md5_fuzzer(void);
int			md5_tester(void *message, uint32_t *to_test_digest, uint64_t len);
#endif
