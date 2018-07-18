NAME= ft_ssl_md5
SRC= srcs/main.c
HDRS= includes/ft_ssl_md5.h
OBJ= $(SRC:.c=.o)
CC= gcc
CC_FLAGS= -v  -Wall -Werror -Wextra -Weverything  -g3 -fsanitize=address -fsanitize-blacklist=my_ignores.txt
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
