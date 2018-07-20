/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_command_line.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 15:26:39 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/20 16:25:34 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

/* t_flags	*parse_command_args(int argc, char **argv) */
/* { */
/* 	const static t_parse_callback	callbacks[] = { */
/* 		{&ft_append_flag_callback, SCRIPT_FLAGS[0], {0}}, */
/* 		{&ft_no_sleep_flag_callback, SCRIPT_FLAGS[1], {0}}, */
/* 		{&ft_pipe_flag_callback, SCRIPT_FLAGS[2], {0}}, */
/* 		{&ft_keylog_flag_callback, SCRIPT_FLAGS[3], {0}}, */
/* 		{&ft_play_back_flag_callback, SCRIPT_FLAGS[4], {0}}, */
/* 		{&ft_quiet_flag_callback, SCRIPT_FLAGS[5], {0}}, */
/* 		{&ft_timestamp_flag_callback, SCRIPT_FLAGS[6], {0}}, */
/* 		{&ft_flush_time_flag_callback, SCRIPT_FLAGS[7], {0}}, */
/* 	}; */
/* 	char							retrieved_opt; */

/* 	while ((retrieved_opt = (char)ft_getopt(argc, argv, SCRIPT_FLAGS_GETOPT)) != -1) */
/* 	{ */
/* 		if (retrieved_opt == GETOPT_ERR_CHAR) */
/* 		{ */
/* 			print_usage(); */
/* 			_exit(EXIT_FAILURE); */
/* 		} */
/* 		if (callbacks[(int)(ft_strchr(SCRIPT_FLAGS, retrieved_opt) */
/* 							- SCRIPT_FLAGS)].callback(&script_info)) */
/* 			break; */
/* 	} */
/* 	post_opt_parsing(argc, argv, env, &script_info); */
/* 	return (&script_info); */
/* } */


const t_hash_identity	g_supported_hashs[SUPPORTED_TYPES] = {
	{"md5", parse_md5, MD5, {0}},
	{"sha256", NULL, SHA256, {0}}
};

static char		*get_cmd_name(char *command_name)
{
	uint32_t	i;

	i = 0;
	while (i < sizeof(g_supported_hashs) / sizeof(t_hash_identity))
	{
		if (!ft_strcmp(command_name, g_supported_hashs[i].name))
			return (g_supported_hashs[i].name);
		i++;
	}
	return (NULL);
}

static t_cmd_type	get_cmd_type(char *command_name)
{
	uint32_t	i;

	i = 0;
	while (i < sizeof(g_supported_hashs) / sizeof(t_hash_identity))
	{
		if (!ft_strcmp(command_name, g_supported_hashs[i].name))
			return (g_supported_hashs[i].type);
		i++;
	}
	return (SUPPORTED_TYPES);
}

static void		display_command_line(t_command_line *cmd)
{
	uint32_t	i;

	i = 0;
	printf("name: %s\n", cmd->command_name);
	while (cmd->argv[i])
	{
		printf("%u arg: %s\n", i, cmd->argv[i]);
		i++;
	}
	printf("type: %d\n", (int)cmd->type);
	printf("argc: %llu\n", cmd->argc);
	printf("flags: p: %hhu q: %hhu  r: %hhu s: %hhu\n", cmd->flags.md5.p, cmd->flags.md5.q, cmd->flags.md5.r, cmd->flags.md5.s);
}


t_command_line	*parse_command_line(int argc, char **argv)
{
	static t_command_line	cmd;
	uint32_t				i;

	ft_bzero(&cmd, sizeof(cmd));
	if (argc < 2)
		return (NULL);
	if (!(cmd.command_name = get_cmd_name(argv[1])))
		ft_error_exit(1, (char*[]){"Unknown command name found"}, EXIT_FAILURE); // add usage
	cmd.argv = argv + 1;
	cmd.argc = (uint64_t)argc - 1;
	cmd.type = get_cmd_type(cmd.command_name);
	i = 0;
	while (i < sizeof(g_supported_hashs) / sizeof(*g_supported_hashs))
	{
		if (g_supported_hashs[i].type == cmd.type)
			g_supported_hashs[i].cmd_parse_function((int)cmd.argc, cmd.argv, &cmd);
		i++;
	}
	display_command_line(&cmd);
	return (&cmd);
}
