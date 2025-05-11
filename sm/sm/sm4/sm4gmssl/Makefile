# Makefile for sm4gmssl.c  

# 编译器  
CC = gcc  

# 手动指定 GmSSL 的包含路径和库路径  
GMSSL_INCLUDE = /usr/local/include  
GMSSL_LIB = /usr/local/lib  

# 编译选项  
CFLAGS = -Wall -O2 -I $(GMSSL_INCLUDE)  
LDFLAGS = -L $(GMSSL_LIB) -lgmssl  

# 可执行文件名称  ·
TARGET = sm4gmssl  

# 源文件  
SRCS = sm4gmssl.c  

# 目标文件  
OBJS = $(SRCS:.c=.o)  

# 默认目标  
all: $(TARGET)  

# 链接目标  
$(TARGET): $(OBJS)  
	$(CC) -o $@ $^ $(LDFLAGS)  $(CLAGS)  


# 编译源文件为目标文件  
%.o: %.c  
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@  

# 清理生成的文件  
clean:  
	rm -f $(TARGET) $(OBJS)  

# 伪目标  
.PHONY: all clean
