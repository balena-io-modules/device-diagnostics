const gulp = require('gulp');
const gutil = require('gulp-util');
const typescript = require('gulp-typescript');
const sourcemaps = require('gulp-sourcemaps');
const tsProject = typescript.createProject('tsconfig.json');
const watch = require('gulp-watch');
const srcGlobs = tsProject.config.include;
// Compile the TS sources
gulp.task('typescript', () => {
  tsProject.src()
    .pipe(sourcemaps.init())
    .pipe(tsProject()).on('error', gutil.log)
    .pipe(sourcemaps.write())
    .pipe(gulp.dest(tsProject.options.outDir));
});

// Copy any pre-defined declarations
gulp.task('copydecs', () => {
  const decDirs = [];
  srcGlobs.forEach((dir) => {
    decDirs.push(`${dir.split('/')[0]}/**/*.d.ts`);
  });
  gulp.src(decDirs)
    .pipe(gulp.dest(tsProject.options.declarationDir));
});

gulp.task('watch', function () {
  return watch(srcGlobs, () => {
    gulp.start('build');
  });
});

gulp.task('build', [ 'typescript', 'copydecs' ]);
