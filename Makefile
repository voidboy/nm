CXX			= gcc
NAME		= ft_nm
SRC			= $(wildcard srcs/*.c)
OBJ			= $(SRC:.c=.o)
CXXFLAGS	= -I./inc -Wall -Wextra -g -Werror -D DEBUGGING


all			: $(NAME)

$(NAME)		: $(OBJ) 
			$(CXX) $(CXXFLAGS) -o $@ $^

%.o         : %.c
			$(CXX) $(CXXFLAGS) -o $@ -c $<

clean		:
			rm -rf $(OBJ)

fclean		: clean
			rm -rf $(NAME)

re			: fclean all

reclean		: fclean all clean

.PHONY : all clean fclean re reclean

