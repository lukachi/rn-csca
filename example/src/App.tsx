import { Text, View, StyleSheet } from 'react-native';
import { csca_parser } from 'rn-csca';

console.log({ csca_parser });

export default function App() {
  return (
    <View style={styles.container}>
      <Text>Result: {''}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
