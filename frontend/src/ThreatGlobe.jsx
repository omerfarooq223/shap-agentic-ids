import { useEffect, useMemo, useRef, useState } from 'react';
import { MapPin, TrendingUp } from 'lucide-react';
import * as THREE from 'three';

const FALLBACK_REGIONS = {
  'North America': { lat: 39, lon: -98, color: 0xff3d4d },
  'South America': { lat: -15, lon: -60, color: 0xff6b7a },
  Europe: { lat: 54, lon: 15, color: 0xff3d4d },
  Africa: { lat: 0, lon: 20, color: 0xffc107 },
  'Asia-Pacific': { lat: 30, lon: 120, color: 0x0d9fff },
};

const getCoordinatesFromAlert = (alert) => {
  const statusColor = alert?.status === 'CRITICAL' ? 0xff3d4d : 0x0d9fff;
  const geo = alert?.geo_location;

  if (geo && Number.isFinite(geo.lat) && Number.isFinite(geo.lon)) {
    return {
      lat: geo.lat,
      lon: geo.lon,
      region: geo.country || 'Unknown',
      city: geo.city || '',
      color: statusColor,
    };
  }

  const ip = alert?.src_ip || '205.0.0.0';
  const firstOctet = Number.parseInt(ip.split('.')[0], 10);

  let region = 'Asia-Pacific';
  if (firstOctet >= 1 && firstOctet <= 50) region = 'North America';
  else if (firstOctet >= 51 && firstOctet <= 100) region = 'South America';
  else if (firstOctet >= 101 && firstOctet <= 150) region = 'Europe';
  else if (firstOctet >= 151 && firstOctet <= 200) region = 'Africa';

  return {
    ...FALLBACK_REGIONS[region],
    region,
    city: 'Unknown',
    color: statusColor,
  };
};

const latLonToVector3 = (lat, lon, radius) => {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);

  return new THREE.Vector3(
    -(radius * Math.sin(phi) * Math.cos(theta)),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  );
};

const getRotationToLocation = (lat, lon) => {
  const target = latLonToVector3(lat, lon, 1).normalize();
  const front = new THREE.Vector3(0, 0, 1);
  return new THREE.Quaternion().setFromUnitVectors(target, front);
};

const createFallbackEarthTexture = () => {
  const canvas = document.createElement('canvas');
  canvas.width = 2048;
  canvas.height = 1024;
  const ctx = canvas.getContext('2d');

  const ocean = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
  ocean.addColorStop(0, '#001a4d');
  ocean.addColorStop(0.5, '#0d3d7d');
  ocean.addColorStop(1, '#001a4d');
  ctx.fillStyle = ocean;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = 'rgba(43, 130, 72, 0.88)';
  const land = [
    { x: 130, y: 360, w: 300, h: 250 },
    { x: 220, y: 640, w: 180, h: 220 },
    { x: 710, y: 280, w: 200, h: 160 },
    { x: 820, y: 470, w: 200, h: 320 },
    { x: 1080, y: 280, w: 560, h: 320 },
    { x: 1620, y: 700, w: 150, h: 120 },
    { x: 0, y: 900, w: canvas.width, h: 124 },
  ];

  land.forEach((p) => ctx.fillRect(p.x, p.y, p.w, p.h));

  ctx.strokeStyle = 'rgba(160, 220, 180, 0.2)';
  ctx.lineWidth = 1;
  for (let y = 0; y <= canvas.height; y += 85) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(canvas.width, y);
    ctx.stroke();
  }
  for (let x = 0; x <= canvas.width; x += 170) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, canvas.height);
    ctx.stroke();
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
};

const ThreatGlobe = ({ alerts }) => {
  const containerRef = useRef(null);
  const sceneRef = useRef(null);
  const cameraRef = useRef(null);
  const rendererRef = useRef(null);
  const globeGroupRef = useRef(null);
  const markersRef = useRef([]);
  const mouseRef = useRef(new THREE.Vector2());
  const raycasterRef = useRef(new THREE.Raycaster());
  const currentQRef = useRef(new THREE.Quaternion());
  const targetQRef = useRef(new THREE.Quaternion());
  const focusUntilRef = useRef(0);
  const lastFocusIdRef = useRef(null);
  const lastAlertCountRef = useRef(0);

  const [tooltip, setTooltip] = useState({ show: false, x: 0, y: 0, data: null, location: '' });
  const isDraggingRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const sortedAlerts = useMemo(() => (Array.isArray(alerts) ? [...alerts] : []), [alerts]);

  const { stats, regionData } = useMemo(() => {
    if (!sortedAlerts.length) {
      return { stats: { total: 0, critical: 0, avgRisk: 0, regions: 0 }, regionData: [] };
    }
    const regionMap = {};
    let totalRisk = 0;
    let criticalCount = 0;
    sortedAlerts.forEach((alert) => {
      const coords = getCoordinatesFromAlert(alert);
      const riskScore = Number.parseFloat(alert?.risk_score || 0);
      if (!regionMap[coords.region]) {
        regionMap[coords.region] = { count: 0, critical: 0, totalRisk: 0, color: coords.color };
      }
      regionMap[coords.region].count += 1;
      regionMap[coords.region].totalRisk += riskScore;
      if (alert?.status === 'CRITICAL') criticalCount += 1;
      totalRisk += riskScore;
    });
    const regions = Object.entries(regionMap).map(([name, data]) => ({
      name, count: data.count, critical: data.critical, avgRisk: (data.totalRisk / data.count).toFixed(1), color: data.color
    }));
    return {
      stats: { total: sortedAlerts.length, critical: criticalCount, avgRisk: (totalRisk / sortedAlerts.length).toFixed(1), regions: regions.length },
      regionData: regions
    };
  }, [sortedAlerts]);


  useEffect(() => {
    const currentContainer = containerRef.current;
    if (!currentContainer) return undefined;

    const scene = new THREE.Scene();
    sceneRef.current = scene;

    const camera = new THREE.PerspectiveCamera(
      55,
      currentContainer.clientWidth / currentContainer.clientHeight,
      0.1,
      2000
    );
    camera.position.set(0, 0.25, 3);
    camera.lookAt(0, 0, 0);
    cameraRef.current = camera;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(800, 560); // temporary size — ResizeObserver corrects this
    renderer.setClearColor(0x070a13, 1);
    const canvas = renderer.domElement;
    canvas.style.position = 'absolute';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.display = 'block';
    currentContainer.appendChild(canvas);
    rendererRef.current = renderer;

    const group = new THREE.Group();
    globeGroupRef.current = group;
    scene.add(group);

    const loader = new THREE.TextureLoader();
    loader.setCrossOrigin('anonymous');

    const earthTextureUrl = 'https://threejs.org/examples/textures/land_ocean_ice_cloud_2048.jpg';

    const makeGlobe = (earthTexture) => {
      earthTexture.colorSpace = THREE.SRGBColorSpace;
      earthTexture.anisotropy = renderer.capabilities.getMaxAnisotropy();

      const globe = new THREE.Mesh(
        new THREE.SphereGeometry(1, 128, 128),
        new THREE.MeshPhongMaterial({
          map: earthTexture,
          shininess: 10,
          specular: new THREE.Color(0x1a355e),
        })
      );
      group.add(globe);

      const atmosphere = new THREE.Mesh(
        new THREE.SphereGeometry(1.06, 64, 64),
        new THREE.MeshBasicMaterial({
          color: 0x4db8ff,
          transparent: true,
          opacity: 0.16,
          side: THREE.BackSide,
        })
      );
      group.add(atmosphere);

      return { globe, atmosphere };
    };

    try {
      loader.load(
        earthTextureUrl,
        (tex) => makeGlobe(tex),
        undefined,
        () => makeGlobe(createFallbackEarthTexture())
      );
    } catch {
      makeGlobe(createFallbackEarthTexture());
    }

    scene.add(new THREE.AmbientLight(0xffffff, 0.62));

    const sun = new THREE.DirectionalLight(0xffffff, 0.95);
    sun.position.set(4, 2, 3);
    scene.add(sun);

    const fill = new THREE.PointLight(0x0d9fff, 0.6);
    fill.position.set(-4, -2, -3);
    scene.add(fill);

    const stars = new THREE.BufferGeometry();
    const starVertices = [];
    for (let i = 0; i < 1200; i += 1) {
      starVertices.push((Math.random() - 0.5) * 120, (Math.random() - 0.5) * 120, (Math.random() - 0.5) * 120);
    }
    stars.setAttribute('position', new THREE.Float32BufferAttribute(starVertices, 3));
    scene.add(new THREE.Points(stars, new THREE.PointsMaterial({ color: 0xffffff, size: 0.02 })));



    const onMove = (event) => {
      if (!currentContainer) return;
      const rect = currentContainer.getBoundingClientRect();
      const x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      mouseRef.current.set(x, y);
      setTooltip((prev) => ({ ...prev, x: event.clientX, y: event.clientY }));

      if (isDraggingRef.current) {
        const deltaX = event.clientX - lastMouseRef.current.x;
        const deltaY = event.clientY - lastMouseRef.current.y;

        const rotY = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(0, 1, 0), deltaX * 0.008);
        const rotX = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(1, 0, 0), deltaY * 0.008);

        targetQRef.current.premultiply(rotY);
        targetQRef.current.premultiply(rotX);

        focusUntilRef.current = Date.now() + 2000;
      }

      lastMouseRef.current = { x: event.clientX, y: event.clientY };
    };

    const onDown = (event) => {
      isDraggingRef.current = true;
      lastMouseRef.current = { x: event.clientX, y: event.clientY };
    };

    const onUp = () => {
      isDraggingRef.current = false;
    };

    const onResize = () => {
      if (!currentContainer || !cameraRef.current || !rendererRef.current) return;
      const w = currentContainer.clientWidth;
      const h = currentContainer.clientHeight;
      if (w === 0 || h === 0) return;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h, false); // false = don't update style (we use CSS 100%)
    };

    // ResizeObserver fires immediately with correct layout dimensions
    const ro = new ResizeObserver(onResize);
    ro.observe(currentContainer);
    currentContainer.addEventListener('mousemove', onMove);
    currentContainer.addEventListener('mousedown', onDown);
    window.addEventListener('mouseup', onUp);

    let rafId = 0;
    const tick = () => {
      rafId = requestAnimationFrame(tick);

      const now = Date.now();
      if (now > focusUntilRef.current) {
        // Auto-drift disabled per user request. 
        // Globe only moves on manual drag or during an attack.
      }

      currentQRef.current.slerp(targetQRef.current, 0.15); // Faster lerp for better responsiveness
      if (globeGroupRef.current) globeGroupRef.current.quaternion.copy(currentQRef.current);

      if (cameraRef.current) {
        raycasterRef.current.setFromCamera(mouseRef.current, cameraRef.current);
        const markerMeshes = markersRef.current.filter((m) => m.type === 'Mesh' && m.userData?.isMarker);
        const intersects = raycasterRef.current.intersectObjects(markerMeshes, false);

        if (intersects.length > 0) {
          const marker = intersects[0].object;
          marker.scale.setScalar(1.35);
          setTooltip((prev) => ({
            ...prev,
            show: true,
            data: marker.userData.alert,
            location: marker.userData.location,
          }));
        } else {
          setTooltip((prev) => ({ ...prev, show: false }));
          markerMeshes.forEach((m) => m.scale.setScalar(1));
        }
      }

      markersRef.current.forEach((obj) => {
        if (obj.type === 'Mesh' && obj.userData?.isMarker) {
          const base = obj.userData.basePosition;
          const pulseRadius = 1.05 + Math.sin(now * 0.003 + obj.userData.seed) * 0.03;
          obj.position.copy(base).normalize().multiplyScalar(pulseRadius);
          obj.scale.setScalar(1 + Math.sin(now * 0.004 + obj.userData.seed) * 0.18);
        }
      });

      renderer.render(scene, camera);
    };

    tick();

    return () => {
      ro.disconnect();
      currentContainer?.removeEventListener('mousemove', onMove);
      currentContainer?.removeEventListener('mousedown', onDown);
      window.removeEventListener('mouseup', onUp);
      cancelAnimationFrame(rafId);
      renderer.dispose();
      currentContainer?.removeChild(renderer.domElement);
    };
  }, []);

  useEffect(() => {
    if (!sceneRef.current || !globeGroupRef.current) return;

    markersRef.current.forEach((obj) => globeGroupRef.current.remove(obj));
    markersRef.current = [];

    if (!sortedAlerts.length) return;


    sortedAlerts.forEach((alert, index) => {
      const coords = getCoordinatesFromAlert(alert);

      const position = latLonToVector3(coords.lat, coords.lon, 1.05);

      const marker = new THREE.Mesh(
        new THREE.IcosahedronGeometry(0.038, 2),
        new THREE.MeshBasicMaterial({ color: coords.color })
      );
      marker.position.copy(position);
      marker.userData = {
        seed: index,
        alert,
        location: `${coords.city ? `${coords.city}, ` : ''}${coords.region}`,
        isMarker: true,
        basePosition: position.clone(),
      };

      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.055, 0.075, 32),
        new THREE.MeshBasicMaterial({
          color: coords.color,
          transparent: true,
          opacity: 0.45,
          side: THREE.DoubleSide,
        })
      );
      ring.position.copy(position);
      ring.lookAt(new THREE.Vector3(0, 0, 0));

      const lineGeo = new THREE.BufferGeometry().setAttribute(
        'position',
        new THREE.BufferAttribute(new Float32Array([0, 0, 0, position.x, position.y, position.z]), 3)
      );
      const line = new THREE.Line(
        lineGeo,
        new THREE.LineBasicMaterial({ color: coords.color, transparent: true, opacity: 0.28 })
      );

      globeGroupRef.current.add(marker);
      globeGroupRef.current.add(ring);
      globeGroupRef.current.add(line);
      markersRef.current.push(marker, ring, line);
    });

    // ── Rotation Logic ──
    const focusAlert = sortedAlerts.find((a) => a?.status === 'CRITICAL') || sortedAlerts[0];
    const newAlertDetected = sortedAlerts.length > lastAlertCountRef.current;

    if (focusAlert && (newAlertDetected || focusAlert.status === 'CRITICAL')) {
      const coords = getCoordinatesFromAlert(focusAlert);
      const focusId = focusAlert?.id ?? `${focusAlert?.src_ip}-${focusAlert?.timestamp}`;

      if (focusId !== lastFocusIdRef.current) {
        // Rotate to the threat origin
        targetQRef.current.copy(getRotationToLocation(coords.lat, coords.lon));
        focusUntilRef.current = Date.now() + 4000; // Lock focus for 4 seconds
        lastFocusIdRef.current = focusId;
      }
    }
    lastAlertCountRef.current = sortedAlerts.length;

  }, [sortedAlerts]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', height: '100%' }}>
      <style>{`
        .globe-container {
          position: relative;
          width: 100%;
          height: 520px;
          background: radial-gradient(circle at 20% 20%, #182236 0%, #0d121e 60%, #090d16 100%);
          border: 1px solid rgba(13, 159, 255, 0.25);
          border-radius: 20px;
          overflow: hidden;
          box-shadow: 
            0 20px 60px rgba(0, 0, 0, 0.5),
            0 0 40px rgba(13, 159, 255, 0.1),
            inset 0 1px 0 rgba(255, 255, 255, 0.08);
          cursor: crosshair;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 300ms cubic-bezier(0.4, 0, 0.2, 1);
        }

        .globe-container:hover {
          box-shadow: 
            0 24px 70px rgba(0, 0, 0, 0.6),
            0 0 50px rgba(13, 159, 255, 0.15),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
          border-color: rgba(13, 159, 255, 0.4);
        }

        .globe-tooltip {
          position: fixed;
          background: linear-gradient(135deg, rgba(13, 17, 23, 0.96) 0%, rgba(7, 10, 19, 0.96) 100%);
          border: 1px solid rgba(13, 159, 255, 0.5);
          padding: 14px 16px;
          border-radius: 10px;
          pointer-events: none;
          z-index: 1000;
          font-family: 'IBM Plex Mono', monospace;
          box-shadow: 
            0 8px 32px rgba(13, 159, 255, 0.25),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
          backdrop-filter: blur(12px);
          transform: translate(15px, 15px);
          min-width: 200px;
          animation: tooltip-fade 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes tooltip-fade {
          from { 
            opacity: 0; 
            transform: translate(15px, 25px) scale(0.9);
          }
          to { 
            opacity: 1; 
            transform: translate(15px, 15px) scale(1);
          }
        }

        .tooltip-header {
          color: #0d9fff;
          font-size: 0.7rem;
          font-weight: 700;
          margin-bottom: 10px;
          border-bottom: 1px solid rgba(13, 159, 255, 0.3);
          padding-bottom: 6px;
          display: flex;
          align-items: center;
          gap: 6px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .tooltip-row {
          display: flex;
          justify-content: space-between;
          font-size: 0.8rem;
          margin-bottom: 5px;
          gap: 12px;
        }

        .tooltip-row:last-child {
          margin-bottom: 0;
        }

        .tooltip-label { 
          color: rgba(255, 255, 255, 0.5);
          font-weight: 500;
        }

        .tooltip-val { 
          color: #fff; 
          font-weight: 700;
          font-family: 'IBM Plex Mono', monospace;
        }

        canvas { 
          display: block;
          width: 100%;
          height: 100%;
          filter: drop-shadow(0 0 20px rgba(13, 159, 255, 0.1));
        }

        .globe-overlay {
          position: absolute;
          top: 24px;
          left: 24px;
          color: rgba(255, 255, 255, 0.75);
          font-family: 'IBM Plex Mono', monospace;
          font-size: 0.75rem;
          text-transform: uppercase;
          letter-spacing: 1.2px;
          z-index: 20;
          display: flex;
          flex-direction: column;
          gap: 6px;
          backdrop-filter: blur(8px);
          background: rgba(7, 10, 19, 0.4);
          border: 1px solid rgba(13, 159, 255, 0.2);
          padding: 12px 16px;
          border-radius: 8px;
          animation: slideInDown 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes slideInDown {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .globe-overlay small {
          color: rgba(180, 210, 255, 0.8);
          text-transform: none;
          letter-spacing: 0;
          font-size: 0.7rem;
        }

        .threat-pulse {
          display: inline-block;
          width: 8px;
          height: 8px;
          background: #ff3d4d;
          border-radius: 50%;
          margin-right: 8px;
          box-shadow: 0 0 12px #ff3d4d;
          animation: pulse-mini 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }

        @keyframes pulse-mini {
          0%, 100% { 
            transform: scale(1); 
            opacity: 1; 
            box-shadow: 0 0 12px #ff3d4d;
          }
          50% { 
            transform: scale(1.5); 
            opacity: 0.5;
            box-shadow: 0 0 20px #ff3d4d;
          }
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 20px;
        }

        .stat-card {
          background: linear-gradient(135deg, rgba(13, 159, 255, 0.1) 0%, rgba(13, 159, 255, 0.05) 100%);
          border: 1px solid rgba(13, 159, 255, 0.25);
          border-radius: 14px;
          padding: 10px 18px;
          transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
          position: relative;
          overflow: hidden;
          height: fit-content;
        }

        .stat-card::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 1px;
          background: linear-gradient(90deg, transparent, rgba(13, 159, 255, 0.5), transparent);
          opacity: 0;
          transition: opacity 250ms;
        }

        .stat-card:hover {
          border-color: rgba(13, 159, 255, 0.4);
          box-shadow: 0 8px 24px rgba(13, 159, 255, 0.12);
          transform: translateY(-4px);
        }

        .stat-card:hover::before {
          opacity: 1;
        }

        .stat-card.critical { 
          border-color: rgba(255, 61, 77, 0.25);
          background: linear-gradient(135deg, rgba(255, 61, 77, 0.1) 0%, rgba(255, 61, 77, 0.05) 100%);
        }

        .stat-card.critical:hover {
          border-color: rgba(255, 61, 77, 0.4);
          box-shadow: 0 8px 24px rgba(255, 61, 77, 0.12);
        }

        .stat-label {
          font-size: 0.75rem;
          color: rgba(255, 255, 255, 0.6);
          text-transform: uppercase;
          font-weight: 600;
          letter-spacing: 0.8px;
          margin-bottom: 10px;
        }

        .stat-value {
          font-size: 1.8rem;
          font-weight: 800;
          font-family: 'IBM Plex Mono', monospace;
          color: #0d9fff;
          text-shadow: 0 0 15px rgba(13, 159, 255, 0.3);
          letter-spacing: -0.5px;
        }

        .stat-card.critical .stat-value {
          color: #ff3d4d;
          text-shadow: 0 0 15px rgba(255, 61, 77, 0.3);
        }

        .regions-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
          gap: 20px;
        }

        .region-card {
          background: linear-gradient(135deg, #14181f 0%, #1a1f2e 100%);
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 14px;
          padding: 12px 20px;
          position: relative;
          overflow: hidden;
          transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
        }

        .region-card::before {
          content: '';
          position: absolute;
          top: 0; left: 0; right: 0;
          height: 3px;
          background: linear-gradient(90deg, var(--region-color), transparent);
          box-shadow: 0 0 15px var(--region-color);
          opacity: 0;
          transition: opacity 250ms;
        }

        .region-card:hover {
          border-color: rgba(255, 255, 255, 0.2);
          box-shadow: 0 8px 28px rgba(13, 159, 255, 0.08);
          transform: translateY(-4px);
          background: linear-gradient(135deg, #15191f 0%, #1b202f 100%);
        }

        .region-card:hover::before {
          opacity: 1;
        }

        .region-name {
          font-family: 'Syne', sans-serif;
          font-size: 1.05rem;
          font-weight: 700;
          color: var(--text-primary);
          margin-bottom: 14px;
          display: flex;
          align-items: center;
          gap: 10px;
          letter-spacing: 0.3px;
        }

        .region-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: var(--region-color);
          box-shadow: 0 0 14px var(--region-color);
          animation: dot-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }

        @keyframes dot-pulse {
          0%, 100% { 
            box-shadow: 0 0 14px var(--region-color);
          }
          50% { 
            box-shadow: 0 0 20px var(--region-color);
          }
        }

        .region-stats {
          display: flex;
          flex-direction: column;
          gap: 10px;
          font-size: 0.85rem;
          font-family: 'IBM Plex Mono', monospace;
        }

        .region-stat {
          display: flex;
          justify-content: space-between;
          color: rgba(255, 255, 255, 0.65);
          font-weight: 500;
        }

        .region-stat-val {
          color: var(--region-color);
          font-weight: 800;
          text-shadow: 0 0 8px rgba(0, 0, 0, 0.3);
        }

        .section-title {
          font-family: 'Syne', sans-serif;
          font-size: 0.95rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-top: 8px;
          margin-bottom: 20px;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .section-title svg {
          filter: drop-shadow(0 0 8px rgba(13, 159, 255, 0.2));
        }

        .section-divider {
          height: 1px;
          background: linear-gradient(90deg, transparent, rgba(13, 159, 255, 0.2), transparent);
          margin: 8px 0;
        }
      `}</style>

      {/* Tooltip */}
      {tooltip.show && (
        <div className="globe-tooltip" style={{ left: tooltip.x, top: tooltip.y }}>
          <div className="tooltip-header">
            <MapPin size={12} />
            Threat Origin
          </div>
          <div className="tooltip-row">
            <span className="tooltip-label">Location:</span>
            <span className="tooltip-val">{tooltip.location}</span>
          </div>
          <div className="tooltip-row">
            <span className="tooltip-label">Source IP:</span>
            <span className="tooltip-val" style={{ fontSize: '0.75rem' }}>{tooltip.data?.src_ip}</span>
          </div>
          <div className="tooltip-row">
            <span className="tooltip-label">Threat Type:</span>
            <span
              className="tooltip-val"
              style={{ color: tooltip.data?.status === 'CRITICAL' ? '#ff3d4d' : '#0d9fff' }}
            >
              {tooltip.data?.threat_type}
            </span>
          </div>
          <div className="tooltip-row">
            <span className="tooltip-label">Risk Score:</span>
            <span className="tooltip-val">{tooltip.data?.risk_score}/10</span>
          </div>
        </div>
      )}

      {/* 3D Globe */}
      <div>
        <div className="globe-container" ref={containerRef}>
          <div className="globe-overlay">
            <div>
              <span className="threat-pulse"></span>
              Real-Time Threat Distribution
            </div>
            <small>Geolocation based on source IP addresses. Hover over threats for details.</small>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div>
        <div className="section-divider"></div>
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-label">Total Threats Detected</div>
            <div className="stat-value">{stats.total}</div>
          </div>
          <div className="stat-card critical">
            <div className="stat-label">Critical Severity</div>
            <div className="stat-value">{stats.critical}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Average Risk Score</div>
            <div className="stat-value">{stats.avgRisk}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Regions Affected</div>
            <div className="stat-value">{stats.regions}</div>
          </div>
        </div>
      </div>

      {/* Regional Analysis */}
      {regionData.length > 0 && (
        <div>
          <div className="section-divider"></div>
          <div className="section-title">
            <TrendingUp size={20} />
            Regional Threat Analysis
          </div>
          <div className="regions-grid">
            {regionData.map((region) => (
              <div
                key={region.name}
                className="region-card"
                style={{
                  '--region-color': `rgb(${(region.color >> 16) & 255}, ${(region.color >> 8) & 255}, ${region.color & 255})`,
                }}
              >
                <div className="region-name">
                  <div className="region-dot"></div>
                  {region.name}
                </div>
                <div className="region-stats">
                  <div className="region-stat">
                    <span>Total Threats:</span>
                    <span className="region-stat-val">{region.count}</span>
                  </div>
                  <div className="region-stat">
                    <span>Critical:</span>
                    <span className="region-stat-val">{region.critical}</span>
                  </div>
                  <div className="region-stat">
                    <span>Avg Risk:</span>
                    <span className="region-stat-val">{region.avgRisk}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatGlobe;