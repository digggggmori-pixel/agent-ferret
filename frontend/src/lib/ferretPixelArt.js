// Ferret Pixel Art Engine — box-shadow based rendering
// Ported from design-concepts/ferret-final.html (v2 Cute)

export const C = {
  body:     '#b8834e',
  bodyDk:   '#9a6b38',
  belly:    '#e8d0a8',
  mask:     '#3a2010',
  eye:      '#00ffff',
  eyeHi:    '#ffffff',
  nose:     '#ff69b4',
  blush:    '#ff8888',
  handle:   '#8B7355',
  handleDk: '#6b5535',
  rim:      '#d0d0d0',
  rimHi:    '#f0f0f0',
  lens:     '#7ab8e8',
  lensHi:   '#a8dbff',
  glint:    '#ffffff',
  alert:    '#00ffff',
  spark1:   '#00ffff',
  spark2:   '#ff69b4',
  zzz:      '#6a7080',
};

// Helper: 5x5 magnifying glass at offset (ox, oy)
function magGlass(ox, oy) {
  return [
    [ox+1,oy,C.rimHi],[ox+2,oy,C.rimHi],[ox+3,oy,C.rim],
    [ox,oy+1,C.rim],[ox+4,oy+1,C.rim],
    [ox,oy+2,C.rim],[ox+4,oy+2,C.rim],
    [ox,oy+3,C.rim],[ox+4,oy+3,C.rim],
    [ox+1,oy+4,C.rim],[ox+2,oy+4,C.rim],[ox+3,oy+4,C.rim],
    [ox+1,oy+1,C.glint],[ox+2,oy+1,C.lensHi],[ox+3,oy+1,C.lensHi],
    [ox+1,oy+2,C.lensHi],[ox+2,oy+2,C.lensHi],[ox+3,oy+2,C.lens],
    [ox+1,oy+3,C.lens],[ox+2,oy+3,C.lens],[ox+3,oy+3,C.lens],
  ];
}

// ── POSE: Idle ──
export function idlePixels() {
  return [
    [8,0,C.body],[9,0,C.belly],[12,0,C.belly],[13,0,C.body],
    [7,1,C.body],[8,1,C.body],[9,1,C.body],[10,1,C.body],[11,1,C.body],[12,1,C.body],[13,1,C.body],[14,1,C.body],
    [7,2,C.body],[8,2,C.mask],[9,2,C.eyeHi],[10,2,C.eye],[11,2,C.mask],[12,2,C.eyeHi],[13,2,C.eye],[14,2,C.body],
    [7,3,C.body],[8,3,C.mask],[9,3,C.eye],[10,3,C.eye],[11,3,C.mask],[12,3,C.eye],[13,3,C.eye],[14,3,C.body],
    [7,4,C.body],[8,4,C.blush],[9,4,C.body],[10,4,C.nose],[11,4,C.body],[12,4,C.body],[13,4,C.blush],[14,4,C.body],
    [8,5,C.body],[9,5,C.belly],[10,5,C.belly],[11,5,C.belly],[12,5,C.belly],[13,5,C.body],
    [8,6,C.body],[9,6,C.body],[10,6,C.belly],[11,6,C.belly],[12,6,C.body],[13,6,C.body],
    [9,7,C.body],[10,7,C.belly],[11,7,C.body],[12,7,C.body],
    [8,8,C.bodyDk],[9,8,C.bodyDk],[11,8,C.bodyDk],[12,8,C.bodyDk],
    [13,6,C.body],[14,5,C.body],[15,4,C.body],[15,3,C.bodyDk],
    ...magGlass(0, 2),
    [5,6,C.handle],[6,7,C.handle],[7,8,C.handleDk],
  ];
}

// ── POSE: Investigate / Sniff ──
export function sniffPixels() {
  return [
    ...magGlass(0, 0),
    [5,4,C.handle],[6,5,C.handle],
    [9,0,C.body],[10,0,C.belly],[13,0,C.belly],[14,0,C.body],
    [8,1,C.body],[9,1,C.body],[10,1,C.body],[11,1,C.body],[12,1,C.body],[13,1,C.body],[14,1,C.body],[15,1,C.body],
    [8,2,C.body],[9,2,C.mask],[10,2,C.eyeHi],[11,2,C.eye],[12,2,C.mask],[13,2,C.eyeHi],[14,2,C.eye],[15,2,C.body],
    [8,3,C.body],[9,3,C.mask],[10,3,C.eye],[11,3,C.eye],[12,3,C.mask],[13,3,C.eye],[14,3,C.eye],[15,3,C.body],
    [8,4,C.body],[9,4,C.blush],[10,4,C.body],[11,4,C.nose],[12,4,C.body],[13,4,C.body],[14,4,C.blush],[15,4,C.body],
    [7,5,C.bodyDk],[8,5,C.body],
    [9,5,C.body],[10,5,C.belly],[11,5,C.belly],[12,5,C.belly],[13,5,C.body],
    [9,6,C.body],[10,6,C.body],[11,6,C.belly],[12,6,C.belly],[13,6,C.body],[14,6,C.body],
    [10,7,C.body],[11,7,C.belly],[12,7,C.body],[13,7,C.body],
    [9,8,C.bodyDk],[10,8,C.bodyDk],[12,8,C.bodyDk],[13,8,C.bodyDk],
    [14,5,C.body],[15,4,C.body],[16,3,C.body],[16,2,C.bodyDk],
  ];
}

// ── POSE: Run Frame 1 ──
export function runFrame1() {
  return [
    [5,0,C.body],[6,0,C.belly],
    [4,1,C.body],[5,1,C.body],[6,1,C.body],[7,1,C.body],[8,1,C.body],
    [4,2,C.body],[5,2,C.mask],[6,2,C.eyeHi],[7,2,C.eye],[8,2,C.body],
    [4,3,C.body],[5,3,C.nose],[6,3,C.body],
    [6,3,C.body],[7,3,C.body],[8,3,C.body],[9,3,C.body],
    [5,4,C.body],[6,4,C.belly],[7,4,C.belly],[8,4,C.belly],[9,4,C.body],[10,4,C.body],
    [5,5,C.body],[6,5,C.belly],[7,5,C.belly],[8,5,C.belly],[9,5,C.body],[10,5,C.body],[11,5,C.body],
    [3,6,C.bodyDk],[4,6,C.bodyDk],
    [9,6,C.bodyDk],
    [11,4,C.body],[12,3,C.body],[12,2,C.bodyDk],
    [9,1,C.rim],[10,1,C.rim],
    [8,2,C.rim],[11,2,C.rim],
    [9,2,C.lens],[10,2,C.lensHi],
    [9,3,C.rim],[10,3,C.rim],
    [9,1,C.glint],
    [8,3,C.handle],
  ];
}

// ── POSE: Run Frame 2 ──
export function runFrame2() {
  return [
    [5,0,C.body],[6,0,C.belly],
    [4,1,C.body],[5,1,C.body],[6,1,C.body],[7,1,C.body],[8,1,C.body],
    [4,2,C.body],[5,2,C.mask],[6,2,C.eyeHi],[7,2,C.eye],[8,2,C.body],
    [4,3,C.body],[5,3,C.nose],[6,3,C.body],
    [6,3,C.body],[7,3,C.body],[8,3,C.body],[9,3,C.body],
    [5,4,C.body],[6,4,C.belly],[7,4,C.belly],[8,4,C.belly],[9,4,C.body],[10,4,C.body],
    [5,5,C.body],[6,5,C.belly],[7,5,C.belly],[8,5,C.belly],[9,5,C.body],[10,5,C.body],[11,5,C.body],
    [5,6,C.bodyDk],
    [9,6,C.bodyDk],[10,6,C.bodyDk],
    [11,4,C.body],[12,4,C.body],[12,3,C.bodyDk],
    [9,1,C.rim],[10,1,C.rim],
    [8,2,C.rim],[11,2,C.rim],
    [9,2,C.lens],[10,2,C.lensHi],
    [9,3,C.rim],[10,3,C.rim],
    [9,1,C.glint],
    [8,3,C.handle],
  ];
}

// ── POSE: Found / Alert ──
export function foundPixels() {
  return [
    [10,0,C.alert],[10,1,C.alert],[10,2,C.alert],
    [10,4,C.alert],
    [8,5,C.body],[9,5,C.belly],[12,5,C.belly],[13,5,C.body],
    [7,6,C.body],[8,6,C.body],[9,6,C.body],[10,6,C.body],[11,6,C.body],[12,6,C.body],[13,6,C.body],[14,6,C.body],
    [7,7,C.body],[8,7,C.mask],[9,7,C.eyeHi],[10,7,C.eye],[11,7,C.mask],[12,7,C.eyeHi],[13,7,C.eye],[14,7,C.body],
    [7,8,C.body],[8,8,C.mask],[9,8,C.eye],[10,8,C.eye],[11,8,C.mask],[12,8,C.eye],[13,8,C.eye],[14,8,C.body],
    [8,9,C.blush],[9,9,C.body],[10,9,C.nose],[11,9,C.body],[12,9,C.body],[13,9,C.blush],
    [7,9,C.body],[14,9,C.body],
    [8,10,C.body],[9,10,C.belly],[10,10,C.belly],[11,10,C.belly],[12,10,C.belly],[13,10,C.body],
    [8,11,C.body],[9,11,C.body],[10,11,C.belly],[11,11,C.belly],[12,11,C.body],[13,11,C.body],
    [8,12,C.bodyDk],[9,12,C.bodyDk],[11,12,C.bodyDk],[12,12,C.bodyDk],
    [13,10,C.body],[14,9,C.body],[15,8,C.bodyDk],
    ...magGlass(0, 3),
    [5,7,C.handle],[6,8,C.handle],[7,9,C.handleDk],
  ];
}

// ── POSE: Happy ──
export function happyPixels() {
  return [
    [1,0,C.spark1],
    [14,1,C.spark2],
    [0,5,C.spark1],
    [15,4,C.spark2],
    [2,9,C.spark1],
    [8,1,C.body],[9,1,C.belly],[12,1,C.belly],[13,1,C.body],
    [7,2,C.body],[8,2,C.body],[9,2,C.body],[10,2,C.body],[11,2,C.body],[12,2,C.body],[13,2,C.body],[14,2,C.body],
    [7,3,C.body],[8,3,C.mask],[9,3,C.body],[10,3,C.body],[11,3,C.mask],[12,3,C.body],[13,3,C.body],[14,3,C.mask],
    [7,4,C.body],[8,4,C.blush],[9,4,C.body],[10,4,C.nose],[11,4,C.body],[12,4,C.body],[13,4,C.blush],[14,4,C.body],
    [8,5,C.body],[9,5,C.belly],[10,5,C.belly],[11,5,C.belly],[12,5,C.belly],[13,5,C.body],
    [7,6,C.body],[8,6,C.body],[9,6,C.belly],[10,6,C.belly],[11,6,C.belly],[12,6,C.body],[13,6,C.body],
    [8,7,C.body],[9,7,C.belly],[10,7,C.belly],[11,7,C.body],[12,7,C.body],
    [8,8,C.bodyDk],[9,8,C.bodyDk],[11,8,C.bodyDk],[12,8,C.bodyDk],
    [13,6,C.body],[14,5,C.body],[14,4,C.bodyDk],
    ...magGlass(0, 3),
    [5,7,C.handle],[6,8,C.handle],[7,8,C.handleDk],
  ];
}

// ── POSE: Sleep ──
export function sleepPixels() {
  return [
    [10,0,C.zzz],[11,0,C.zzz],[12,0,C.zzz],
    [12,1,C.zzz],
    [11,2,C.zzz],
    [10,3,C.zzz],[11,3,C.zzz],[12,3,C.zzz],
    [13,1,C.zzz],[14,1,C.zzz],
    [14,2,C.zzz],
    [13,3,C.zzz],[14,3,C.zzz],
    [3,5,C.body],[4,5,C.body],
    [3,6,C.mask],[4,6,C.body],
    [3,7,C.nose],
    [5,4,C.body],[6,4,C.body],[7,4,C.body],[8,4,C.body],[9,4,C.body],[10,4,C.body],
    [4,5,C.body],[5,5,C.body],[6,5,C.belly],[7,5,C.belly],[8,5,C.belly],[9,5,C.body],[10,5,C.body],[11,5,C.body],
    [4,6,C.body],[5,6,C.body],[6,6,C.belly],[7,6,C.belly],[8,6,C.belly],[9,6,C.body],[10,6,C.body],[11,6,C.body],
    [5,7,C.body],[6,7,C.body],[7,7,C.body],[8,7,C.body],[9,7,C.body],[10,7,C.body],
    [11,5,C.body],[12,5,C.bodyDk],[12,4,C.bodyDk],
    ...magGlass(13, 4),
    [13,8,C.handle],[13,9,C.handle],
  ];
}

// ── Rendering Utilities ──

export function pixelsToBoxShadow(pixels, scale) {
  return pixels.map(([x, y, c]) => {
    const px = x * scale;
    const py = y * scale;
    return `${px}px ${py}px 0 ${scale - 1}px ${c}`;
  }).join(',');
}

export function getSpriteDimensions(pixels, scale) {
  let maxX = 0, maxY = 0;
  pixels.forEach(([x, y]) => { if (x > maxX) maxX = x; if (y > maxY) maxY = y; });
  return { width: (maxX + 1) * scale, height: (maxY + 1) * scale };
}

// Map pose name to pixel function
export function getPosePixels(pose) {
  switch (pose) {
    case 'idle':  return idlePixels();
    case 'sniff': return sniffPixels();
    case 'run1':  return runFrame1();
    case 'run2':  return runFrame2();
    case 'found': return foundPixels();
    case 'happy': return happyPixels();
    case 'sleep': return sleepPixels();
    default:      return idlePixels();
  }
}
