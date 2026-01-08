CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
TARGET = proxy
SRC = src/proxy.cpp

all: $(TARGET)

$(TARGET): $(SRC)
  $(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET)

clean:
  rm -f $(TARGET)

