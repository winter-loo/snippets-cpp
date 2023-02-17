// https://www.nowcoder.com/practice/9999764a61484d819056f807d2a91f1e
#include <cctype>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace std;

inline bool IsOp(char c) {
    return c == '+' || c == '-' || c == '*' || c == '/';
}

inline bool IsLeftBracket(char c) {
    return c == '(' || c == '{' || c == '[';
}

inline bool IsRightBracket(char c) {
    return c == ')' || c == '}' || c == ']';
}

void Compute(vector<int>& nums, vector<char>& ops) {
    int a = nums.back();
    nums.pop_back();
    int b = nums.back();
    nums.pop_back();
    char op = ops.back();
    ops.pop_back();
    if (op == '+')
        nums.push_back(a + b);
    else if (op == '-')
        nums.push_back(b - a);
    else if (op == '*')
        nums.push_back(a * b);
    else if (op == '/')
        nums.push_back(b / a);
    else throw runtime_error("invalid operator");
}

bool CanCompute(vector<char>& syms, char op) {
    char p = syms.back();
    if (p == '(')
        return false;
    else if ((p == '+' || p == '-') && (op == '*' || op == '/'))
        return false;
    return true;
}

void Foo(const string& s) {
    string ms;
    ms.push_back('(');
    ms.append(s);
    ms.push_back(')');

    string num;
    bool expect_number = true;
    vector<int> nums;
    vector<char> syms;
    for (int i = 0; i < ms.length(); i++) {
        char c = ms[i];
        if  (IsLeftBracket(c)) {
            syms.push_back('(');
        } else if (IsRightBracket(c)) {
            while (syms.back() != '(') {
                Compute(nums, syms);
            }
            syms.pop_back();
        } else if (expect_number) {
            expect_number = false;
            int j = i;
            if (ms[i] == '+' || ms[i] == '-') ++i;
            while (isdigit(ms[i])) ++i;
            int n = stoi(ms.substr(j, i - j));
            nums.push_back(n);
            --i;
        } else { // is operator
            while (CanCompute(syms, c)) {
                Compute(nums, syms);
            }
            syms.push_back(c);
            expect_number = true;
        }
    }
    cout << nums.back() << endl;
}

int main() {
    string s;
    while (getline(cin, s)) {
        Foo(s);
    }
}
