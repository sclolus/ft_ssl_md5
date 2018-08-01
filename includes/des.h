/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/01 04:56:26 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/01 22:39:02 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DES_H
# define DES_H

# include "ft_ssl_md5.h"

typedef struct	s_des_context
{
	uint8_t		*data;
	uint8_t		*cipher;
	t_se_key	*key;
	uint64_t	total_len;
}				t_des_ctx;

extern const uint32_t	g_initial_permutation_table[64];
extern const uint32_t	g_inverse_permutation_table[64];
extern const uint32_t	g_expansion_table[48];
extern const uint8_t	g_selection_tables[8][64];
extern const uint32_t	g_cipher_permutation_table[32];
extern const uint32_t	g_pc_1[56];
extern const uint32_t	g_pc_2[48];
extern const uint32_t	g_left_shift_schedule[16];

/*
** Error handling
*/

# define DES_NO_KEY_OR_PASSWORD "No key nor password was provided"

#endif
