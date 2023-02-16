#include <iostream>
#include <vector>
#include <memory>
using namespace std;

class List {
  public:
    struct Node {
        unique_ptr<Node> next{};
        int data;

        Node(int i): data(i) {}
    };


    List(const vector<int>& vi) {
        Node* tail = nullptr;
        for (auto i : vi) {
            unique_ptr<Node> node(new Node(i));
            if (!head) {
                head = std::move(node);
                tail = head.get();
            } else {
                tail->next = std::move(node);
                tail = tail->next.get();
            }
        }
    }

    Node* LastItem(int k) {
        Node* p1 = head.get(), *p2 = head.get();
        int i = 0;
        for (; p2 && i < k; i++) p2 = p2->next.get();
        if (i < k) return nullptr;
        while (p2) {
            p1 = p1->next.get();
            p2 = p2->next.get();
        }
        return p1;
    }

  private:
    unique_ptr<Node> head{};
};

int main() {
    while (true) {
    int n, m;
    vector<int> vi;
    if (EOF == scanf("%d", &n)) break;
    for (int i = 0; i < n; i++) {
        if (EOF == scanf("%d", &m)) break;
        vi.push_back(m);
    }
    int k;
    if (EOF == scanf("%d", &k)) break;

    List h(vi);
    cout  << "built ok" << endl;
    const List::Node* p = h.LastItem(k);
    if (p) cout << p->data << endl;
    }
    return 0;
}
// 64 位输出请用 printf("%lld")
