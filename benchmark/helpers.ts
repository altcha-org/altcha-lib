import { Bench } from 'tinybench';

const NAME_MAX_LEN = 40;

export async function benchmark(name: string, initFn: (bench: Bench) => void, duration: number = 500) {
  const bench = new Bench({
    time: duration,
    throws: true,
    warmupTime: 2000,
    warmupIterations: 100,
  });
  initFn(bench);
  await bench.run();
  console.log('>', name);
  for (let row of bench.table()) {
    if (row) {
      console.log(
        '-',
        row['Task Name'].slice(0, NAME_MAX_LEN).padEnd(NAME_MAX_LEN, '.'),
        row['ops/sec'].padStart(10, ' '),
        'ops/s',
        row['Margin'],
      );
    }
  }
  console.log('');
}