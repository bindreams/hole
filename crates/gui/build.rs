use std::path::Path;

fn main() {
    let icons_dir = Path::new("icons");
    let svg_path = icons_dir.join("icon.svg");

    println!("cargo:rerun-if-changed={}", svg_path.display());

    generate_icons(&svg_path, icons_dir);

    tauri_build::build();
}

fn generate_icons(svg_path: &Path, out_dir: &Path) {
    let svg_data = std::fs::read(svg_path).expect("failed to read icon.svg");
    let tree =
        resvg::usvg::Tree::from_data(&svg_data, &resvg::usvg::Options::default()).expect("failed to parse icon.svg");

    // Generate PNGs at required sizes
    for size in [32u32, 128] {
        let png_path = out_dir.join(format!("{size}x{size}.png"));
        render_png(&tree, size, &png_path);
    }

    // Generate ICO (contains 16x16 + 32x32 + 256x256)
    let ico_path = out_dir.join("icon.ico");
    render_ico(&tree, &ico_path);

    // Generate ICNS placeholder (Tauri expects it but only uses on macOS)
    let icns_path = out_dir.join("icon.icns");
    if !icns_path.exists() {
        // Write a minimal valid ICNS with the 128x128 PNG embedded
        let png_data = std::fs::read(out_dir.join("128x128.png")).unwrap();
        write_icns(&icns_path, &png_data);
    }
}

fn render_to_rgba(tree: &resvg::usvg::Tree, size: u32) -> Vec<u8> {
    let mut pixmap = resvg::tiny_skia::Pixmap::new(size, size).unwrap();
    let scale_x = size as f32 / tree.size().width();
    let scale_y = size as f32 / tree.size().height();
    let transform = resvg::tiny_skia::Transform::from_scale(scale_x, scale_y);
    resvg::render(tree, transform, &mut pixmap.as_mut());
    pixmap.data().to_vec()
}

fn render_png(tree: &resvg::usvg::Tree, size: u32, path: &Path) {
    let rgba = render_to_rgba(tree, size);
    let file = std::fs::File::create(path).unwrap();
    let mut encoder = png::Encoder::new(file, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();
    writer.write_image_data(&rgba).unwrap();
}

fn render_ico(tree: &resvg::usvg::Tree, path: &Path) {
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16u32, 32, 256] {
        let rgba = render_to_rgba(tree, size);
        let image = ico::IconImage::from_rgba_data(size, size, rgba);
        icon_dir.add_entry(ico::IconDirEntry::encode(&image).unwrap());
    }
    let file = std::fs::File::create(path).unwrap();
    icon_dir.write(file).unwrap();
}

fn write_icns(path: &Path, png_data: &[u8]) {
    // Minimal ICNS: magic + size header, then ic07 (128x128 PNG) entry
    let entry_size = (8 + png_data.len()) as u32;
    let total_size = 8 + entry_size;
    let mut buf = Vec::with_capacity(total_size as usize);
    buf.extend_from_slice(b"icns");
    buf.extend_from_slice(&total_size.to_be_bytes());
    buf.extend_from_slice(b"ic07");
    buf.extend_from_slice(&entry_size.to_be_bytes());
    buf.extend_from_slice(png_data);
    std::fs::write(path, buf).unwrap();
}
