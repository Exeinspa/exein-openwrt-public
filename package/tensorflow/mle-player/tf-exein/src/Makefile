PROJECT_BINARY_NAME = tf-exein
PROJECT_SOURCES = tfexein.cc


all:	$(PROJECT_BINARY_NAME)

$(PROJECT_BINARY_NAME):	$(PROJECT_SOURCES)
	$(CXX) -std=c++14 -funwind-tables -I/usr/include/xtensor -I. $(CXXFLAGS) $(PROJECT_SOURCES) -o $(PROJECT_BINARY_NAME) -ltensorflow-lite -lflatbuffers -lexnl


clean:
	rm -f $(PROJECT_BINARY_NAME)
