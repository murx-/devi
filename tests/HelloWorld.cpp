#include <cstdlib>
#include <iostream>
#include <time.h>
#include <iostream>

using namespace std;

class Hello {
    public:
    Hello() {}
    virtual void printWorld() { cout << "Hello" << endl; }
};

class HelloWorld : public Hello {
    public:
    HelloWorld() {}
    virtual void printWorld() { cout << "Hello World" << endl;  }
};


int main(int argc, char **argv) {

    Hello *my_hello;
    my_hello = new HelloWorld();
    my_hello->printWorld();
    
    return 0;
}
