NAME= ft_ssl
SRC= srcs/main.c \
	srcs/print_memory.c \
	srcs/md5.c \
	srcs/md5_fuzzer.c \
	srcs/md5_tester.c \
	srcs/sha256.c \
	srcs/hash_tester.c \
	srcs/hash_fuzzer.c \
	srcs/parsing/parse_command_line.c \
	srcs/parsing/parse_md5.c \
	srcs/usage.c

HDRS= includes/ft_ssl_md5.h
OBJ= $(SRC:.c=.o)
CC= gcc
CC_FLAGS= -v  -Wall -Werror -Wextra -Weverything  -O0 -g3 -fsanitize=address -fsanitize-blacklist=my_ignores.txt
LIBFT_PATH=./libft/
FLAGS= -I./libft/includes -I./includes

all: submodule $(NAME)

submodule:
	@make -C libft/

$(NAME): $(OBJ)
	$(CC) $(CC_FLAGS) $(FLAGS) -L./libft -lft $^  -o $(NAME)
%.o : %.c $(HDRS)
	$(CC) $(CC_FLAGS) $(FLAGS) $< -c -o $@

clean:
	rm -f $(OBJ)
	make -C $(LIBFT_PATH) clean
fclean: clean
	rm -f $(NAME)
	make -C $(LIBFT_PATH) fclean

re: fclean all
