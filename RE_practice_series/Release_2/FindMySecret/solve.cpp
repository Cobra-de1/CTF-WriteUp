/*
                ******
		
        Author: Nguyen Phuc Chuong

                ******
*/

#include <bits/stdc++.h>

using namespace std;

int main() {
	ios::sync_with_stdio(false);
	cin.tie(0);
	for (double i = 1; i < 50; i++) {
		double f = i / 50.0;
		for (int j = 0; j < 5; j++) {
			f = 3.8 * f * (1.0 - f);
		}
		cout << int(i) << ": " << f * 10000 << '\n';
	}
	return 0;
}
