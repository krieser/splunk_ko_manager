import SwiftUI

struct ContentView: View {
    // State variables trigger UI updates when their values change
    @State private var die1: Int = 1
    @State private var die2: Int = 1
    @State private var score: Int = 2
    @State private var isRolling: Bool = false

    var body: some View {
        VStack(spacing: 40) {
            Text("Dice Roll")
                .font(.largeTitle)
                .bold()

            // Dice Display
            HStack(spacing: 30) {
                DieView(value: die1)
                DieView(value: die2)
            }
            .rotationEffect(.degrees(isRolling ? 360 : 0))

            // Current Score
            Text("Total: \(score)")
                .font(.title2)
                .fontWeight(.semibold)

            // Roll Button
            Button(action: rollDice) {
                Text("Roll Dice")
                    .font(.title3)
                    .bold()
                    .foregroundColor(.white)
                    .frame(width: 200, height: 50)
                    .background(Color.blue)
                    .cornerRadius(12)
                    .shadow(radius: 5)
            }
        }
        .padding()
    }

    // Logic to update dice values with a brief spin animation
    private func rollDice() {
        withAnimation(.spring(response: 0.4, dampingFraction: 0.6)) {
            isRolling.toggle()
            die1 = Int.random(in: 1...6)
            die2 = Int.random(in: 1...6)
            score = die1 + die2
        }
    }
}

// Helper component for individual die UI using SF Symbols
struct DieView: View {
    let value: Int

    var body: some View {
        Image(systemName: "die.face.\(value).fill")
            .resizable()
            .aspectRatio(contentMode: .fit)
            .frame(width: 100, height: 100)
            .foregroundColor(.red)
    }
}
