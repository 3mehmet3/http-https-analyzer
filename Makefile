CXX = clang++
CXXFLAGS = -Wall -Wextra -std=c++11
TARGET = http_analyzer

OPENSSL_INC = /opt/homebrew/opt/openssl@3/include
OPENSSL_LIB = /opt/homebrew/opt/openssl@3/lib

all: $(TARGET)

$(TARGET): http_analyzer.cpp
	$(CXX) $(CXXFLAGS) -I$(OPENSSL_INC) -L$(OPENSSL_LIB) \
		-o $(TARGET) http_analyzer.cpp -lssl -lcrypto

clean:
	rm -f $(TARGET)

.PHONY: all clean
