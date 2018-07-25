/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_hash.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/25 23:56:19 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 00:58:11 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static void				cmd_hash_allocate_strings(t_command_line *cmd, int argc)
{
	if (!(cmd->info.hash.strings_to_hash = malloc(sizeof(char*) * (uint64_t)argc)))
		exit(EXIT_FAILURE);
	ft_bzero(cmd->info.hash.strings_to_hash, sizeof(char*) * (uint64_t)argc);
}

void					cmd_hash_payload(t_command_line *cmd, int argc, char **argv)
{
	(void)argv;
	cmd_hash_allocate_strings(cmd, argc);
}
