/* Benign owned fixture for debugger launch/step/cleanup validation. */
volatile unsigned knife_counter;
int main(void) {
    knife_counter = 7;
    knife_counter += 1;
    return knife_counter == 8 ? 0 : 1;
}
