/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_sha256.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/25 00:24:25 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 22:19:47 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static int32_t			echo_stdin_callback(t_command_line *cmd)
{
	cmd->flags.md5.p = 1;
	return (0);
}

static int32_t			quiet_mode_callback(t_command_line *cmd)
{
	cmd->flags.md5.q = 1;
	return (0);
}

static int32_t			reverse_callback(t_command_line *cmd)
{
	cmd->flags.md5.r = 1;
	return (0);
}

static int32_t			given_string_callback(t_command_line *cmd)
{
	cmd->flags.md5.s = 1;
	cmd->strings_to_hash[cmd->nbr_strings] = g_optarg;
	cmd->nbr_strings++;
	return (0);
}

t_flags					*parse_sha256(int argc
									, char **argv
									, t_command_line *cmd)
{
	const static t_parse_callback	callbacks[] = {
		{&echo_stdin_callback, SHA256_PARSING_FLAGS[0], {0}},
		{&quiet_mode_callback, SHA256_PARSING_FLAGS[1], {0}},
		{&reverse_callback, SHA256_PARSING_FLAGS[2], {0}},
		{&given_string_callback, SHA256_PARSING_FLAGS[3], {0}},
	};
	char							retrieved_opt;

	ft_bzero(&cmd->flags, sizeof(t_flags));
	while ((retrieved_opt = (char)ft_getopt(argc, argv
										, SHA256_PARSING_FLAGS)) != -1)
	{
		if (retrieved_opt == GETOPT_ERR_CHAR)
		{
			print_usage();
			_exit(EXIT_FAILURE);
		}
		if (callbacks[(int)(ft_strchr(SHA256_FLAGS, retrieved_opt)
							- SHA256_FLAGS)].callback(cmd))
			break ;
	}
	cmd->filenames = argv + g_optind;
	cmd->nbr_files = (uint64_t)argc - (uint64_t)g_optind;
	return (&cmd->flags);
}
