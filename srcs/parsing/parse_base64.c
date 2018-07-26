/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_base64.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 01:42:35 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 04:19:28 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static int32_t	decode_mode_callback(t_command_line *cmd)
{
	cmd->info.se.flags.base64.d = 1;
	cmd->info.se.flags.base64.e = 0;
	return (0);
}

static int32_t	encode_mode_callback(t_command_line *cmd)
{
	cmd->info.se.flags.base64.e = 1;
	cmd->info.se.flags.base64.d = 0;
	return (0);
}

static int32_t	input_file_callback(t_command_line *cmd)
{
	if (ft_strcmp("-", g_optarg))
	{
		cmd->info.se.flags.base64.i = 1;
		cmd->info.se.input_file = g_optarg;
	}
	else
	{
		cmd->info.se.flags.base64.i = 0;
		cmd->info.se.input_file = NULL;
	}
	return (0);
}

static int32_t	output_file_callback(t_command_line *cmd)
{
	if (ft_strcmp("-", g_optarg))
	{
		cmd->info.se.flags.base64.o = 1;
		cmd->info.se.output_file = g_optarg;
	}
	else
	{
		cmd->info.se.flags.base64.o = 0;
		cmd->info.se.output_file = NULL;
	}
	return (0);
}


t_flags			*parse_base64(int argc, char **argv, t_command_line *cmd)
{
	const static t_parse_callback	callbacks[] = {
		{&decode_mode_callback, BASE64_FLAGS[0], {0}},
		{&encode_mode_callback, BASE64_FLAGS[1], {0}},
		{&input_file_callback, BASE64_FLAGS[2], {0}},
		{&output_file_callback, BASE64_FLAGS[3], {0}},
	};
	char							retrieved_opt;

	ft_bzero(&cmd->info.se.flags, sizeof(t_flags));
	cmd->info.se.flags.base64.e = 1;
	while ((retrieved_opt = (char)ft_getopt(argc
									, argv, BASE64_PARSING_FLAGS)) != -1)
	{
		if (retrieved_opt == GETOPT_ERR_CHAR)
		{
			print_usage();
			_exit(EXIT_FAILURE);
		}
		if (callbacks[(int)(ft_strchr(BASE64_FLAGS, retrieved_opt)
							- BASE64_FLAGS)].callback(cmd))
			break ;
	}
	/// please insert handling of extra arguments
	return (&cmd->info.se.flags);
}
