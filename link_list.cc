#include <iostream>
#include <memory>
using namespace std;

class List {
 public:
  struct Node {
    unique_ptr<Node> next{};
    int data{};

    Node(int i) : data(i) {}
  };

  List(int i) { head = make_unique<Node>(i); }

  bool Add(int to, int val) {
    Node *p = head.get();
    while (p) {
      if (p->data == to) {
        unique_ptr<Node> t = std::move(p->next);
        unique_ptr<Node> n(new Node(val));
        n->next = std::move(t);
        p->next = std::move(n);
        return true;
      }
      p = p->next.get();
    }
    return false;
  }

  void Pop(int val) {
    if (head == nullptr) return;
    if (head->data == val) {
      head = std::move(head->next);
      return;
    }
    Node *p = head.get();
    while (p->next) {
      if (p->next->data == val) {
        p->next = std::move(p->next->next);
      } else {
        p = p->next.get();
      }
    }
  }

  void Print() {
    Node *p = head.get();
    while (p) {
      cout << p->data << " ";
      p = p->next.get();
    }
    cout << endl;
  }

 private:
  unique_ptr<Node> head{};
};

int main() {
  int n;
  cin >> n;
  int val;
  cin >> val;
  List h(val);

  int to;
  for (int i = 0; i < n - 1; i++) {
    cin >> val;
    cin >> to;
    h.Add(to, val);
  }
  cin >> val;
  h.Pop(val);
  // 5 2 3 2 4 3 5 2 1 4 3
  // 2 -> 5 -> 3 -> 4 -> 1
  h.Print();
}
// 64 位输出请用 printf("%lld")
