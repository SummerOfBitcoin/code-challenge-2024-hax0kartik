#include <stack>
#include <string>
namespace Script {

class Script {
    public:
        Script() = default;
        Script(std::string m) : msg(m) {}
        bool exec(const std::string &instrs);
        void printStack();
        
        auto setMsg(const std::string& m) {
            msg = m;
        }

        auto& getStack() {
            return stack;
        }

        auto clearStack() {
            while (!stack.empty()) {
                stack.pop();
            }
        }

    private:
        std::stack<std::string> stack {};
        std::string msg;
};

}