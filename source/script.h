#include <stack>

namespace Script {

class Script {
    public:
        Script(std::string m) : msg(m) {}
        bool exec(const std::string &instrs);
        void printStack();
    private:
        std::stack<std::string> stack {};
        std::string msg;
};

}