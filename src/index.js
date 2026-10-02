const MODES = {
  showcase: {
    id: 'showcase',
    mc:  [10000, 500000],
    liq: 3000,
    age: [1, 168],
    volLiqMin: 0.5,
    vol1hMin: 300,
    vol1hRatio: 0.05,
    vol5mMin: 500,
    tx5mMin: 3,
    bsRatio: 1.0,
    chgRange: [-50, 100]
  },
  degen: {
    id: 'degen',
    mc:  [30000, 150000],
    liq: 15000,
    age: [6, 48],
    volLiqMin: 3,
    vol1hMin: 2000,
    vol1hRatio: 0.3,
    vol5mMin: 5000,
    tx5mMin: 20,
    bsRatio: 1.5,
    chgRange: [-15, 30]
  },
  sniper: {
    id: 'sniper',
    mc:  [40000, 120000],
    liq: 20000,
    age: [12, 36],
    volLiqMin: 5,
    vol1hMin: 3000,
    vol1hRatio: 0.4,
    vol5mMin: 10000,
    tx5mMin: 30,
    bsRatio: 2.0,
    chgRange: [-10, 25]
  }
};
